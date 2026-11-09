"""The HTTP endpoints and the message handler of the real plugin class, with a fake Matrix client.

Needs maubot (skipped without it): uv run --no-project --python 3.13 --with maubot==0.6.0 --with pytest
--with pytest-aiohttp pytest tests
"""
import asyncio
import json
import logging
import pathlib
import sys
import types
import urllib.parse

import pytest

pytest.importorskip("maubot")
from aiohttp import web  # noqa: E402
from maubot.matrix import MaubotMessageEvent  # noqa: E402
from maubot.plugin_server import PluginWebApp, PrefixResource  # noqa: E402
from mautrix.types import Event, Membership  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import sbx_chat  # noqa: E402
from sbx_chat import core  # noqa: E402

SECRET = "s" * 40
CONTROL = "!control:example.org"
SESSION = "!session:example.org"
FOREIGN = "!foreign:example.org"
OWNER = "@dag:example.org"
BOT = "@code:example.org"
PREFIX = "/_matrix/maubot/plugin/chat"


class FakeApi:
    def __init__(self):
        self.stored = {}

    async def request(self, method, path, **kwargs):
        return self.stored[urllib.parse.unquote(str(path).rsplit("/", 1)[-1])]


class FakeCryptoStore:
    def __init__(self):
        self.dropped = []

    async def remove_outbound_group_session(self, room_id):
        self.dropped.append(room_id)


class FakeCrypto:
    def __init__(self):
        self.plain = {}
        self.crypto_store = FakeCryptoStore()

    async def decrypt_megolm_event(self, evt):
        return Event.deserialize(self.plain[evt.event_id])


class FakeState:
    def __init__(self, type_, sender):
        self.type, self.sender = type_, sender


class FakeClient:
    mxid = BOT
    disable_replies = False

    def __init__(self):
        self.sent, self.created, self.left = [], [], []
        self.api, self.crypto = FakeApi(), FakeCrypto()
        # Who created which room, as the state of the room says.
        self.creators = {SESSION: BOT, FOREIGN: OWNER}

    async def get_state(self, room):
        return [FakeState("m.room.create", self.creators[room])]

    async def send_message(self, room, content):
        self.sent.append((room, "m.room.message", content.serialize()))
        return f"$ev{len(self.sent)}"

    async def send_message_event(self, room, event_type, content):
        self.sent.append((room, str(event_type), content))
        return f"$ev{len(self.sent)}"

    async def send_state_event(self, room, event_type, content):
        self.sent.append((room, str(event_type), content))
        return "$state"

    async def create_room(self, **kwargs):
        self.created.append(kwargs)
        return "!new:example.org"

    async def leave_room(self, room):
        self.left.append(room)


def make_plugin():
    plugin = object.__new__(sbx_chat.SbxChat)
    plugin.config = {"owner": OWNER, "room_id": CONTROL, "secret": SECRET}
    plugin.client = FakeClient()
    plugin.log = logging.getLogger("test")
    plugin.nonces = core.Nonces()
    plugin.inbox = core.Inbox()
    plugin.fresh = asyncio.Condition()
    plugin.own_rooms = {}
    return plugin


@pytest.fixture
async def setup(aiohttp_client):
    """Routed the way maubot 0.6.0 routes plugin web apps: the instance prefix is cut off before the plugin sees it."""
    plugin = make_plugin()
    sub = PluginWebApp()
    for name in dir(plugin):
        for method, path, kwargs in getattr(getattr(plugin, name), "__mb_web_handler__", []):
            sub.add_route(method=method, path=path, handler=getattr(plugin, name), **kwargs)
    instance_path = PREFIX + "/"

    async def handle_plugin_path(request):
        if request.path.startswith(instance_path):
            request = request.clone(rel_url=request.rel_url.with_path(
                request.rel_url.path[len(instance_path) - 1:]).with_query(request.query_string))
            return await sub.handle(request)
        return web.Response(status=404)

    app = web.Application()
    resource = PrefixResource("/_matrix/maubot/plugin")
    resource.add_route("*", handle_plugin_path)
    app.router.register_resource(resource)
    return plugin, await aiohttp_client(app)


async def call(client, path, data=None, secret=SECRET):
    body = json.dumps(data).encode() if data is not None else b""
    headers = core.sign_request(secret.encode(), "POST", path, body)
    resp = await client.request("POST", PREFIX + path, data=body, headers=headers)
    raw = await resp.read()
    signed = core.check_response(SECRET.encode(), headers["X-Sbx-Nonce"], resp.status, raw,
                                 resp.headers.get("X-Sbx-Mac", ""))
    return resp.status, json.loads(raw), signed


_counter = iter(range(1, 10_000))


def message(plugin, body, room=SESSION, sender=OWNER, encrypted=True, msgtype="m.text", extra=None):
    """A message as maubot hands it to the plugin (a MaubotMessageEvent without the "mautrix" marker); the server's
    copy is m.room.encrypted or plain."""
    event_id = f"$msg{next(_counter)}"
    content = dict({"msgtype": msgtype, "body": body}, **(extra or {}))
    plain = {"type": "m.room.message", "room_id": room, "event_id": event_id, "sender": sender,
             "origin_server_ts": 1, "content": content}
    if encrypted:
        plugin.client.api.stored[event_id] = dict(plain, type="m.room.encrypted", content={
            "algorithm": "m.megolm.v1.aes-sha2", "ciphertext": "x", "session_id": "s", "sender_key": "k",
            "device_id": "DEV"})
        plugin.client.crypto.plain[event_id] = plain
    else:
        plugin.client.api.stored[event_id] = plain
    return MaubotMessageEvent(Event.deserialize(plain), plugin.client)


async def test_owner_message_is_queued(setup):
    plugin, client = setup
    await plugin.on_message(message(plugin, "hello"))
    await plugin.on_message(message(plugin, "in control", room=CONTROL))
    status, body, signed = await call(client, "/events", {"wait": 0})
    assert (status, signed) == (200, True)
    assert [(e["room"], e["text"]) for e in body["events"]] == [(SESSION, "hello"), (CONTROL, "in control")]
    again = await call(client, "/events", {"epoch": body["epoch"], "after": 1})
    assert [e["text"] for e in again[1]["events"]] == ["in control"]


def member(room, who, membership, sender=None):
    return types.SimpleNamespace(room_id=room, state_key=who, sender=sender or who,
                                 content=types.SimpleNamespace(membership=membership))


async def test_owner_join_drops_the_group_session(setup):
    """The session made while the owner was only invited was shared with nobody else; a join must replace it."""
    plugin, _ = setup
    await plugin.on_member(member(SESSION, OWNER, Membership.JOIN))
    assert plugin.client.crypto.crypto_store.dropped == [SESSION]


async def test_other_membership_changes_keep_the_group_session(setup):
    plugin, _ = setup
    other = "@other:example.org"
    await plugin.on_member(member(SESSION, other, Membership.JOIN))                # someone else
    await plugin.on_member(member(SESSION, OWNER, Membership.INVITE, sender=BOT))  # the invitation itself
    await plugin.on_member(member(SESSION, OWNER, Membership.LEAVE))
    await plugin.on_member(member(SESSION, OWNER, Membership.JOIN, sender=other))  # not the owner's own join
    await plugin.on_member(member(FOREIGN, OWNER, Membership.JOIN))                # a room the bot did not create
    assert plugin.client.crypto.crypto_store.dropped == []


async def test_everything_else_is_ignored(setup):
    plugin, client = setup
    await plugin.on_message(message(plugin, "x", sender="@other:example.org"))
    await plugin.on_message(message(plugin, "x", sender=BOT))
    await plugin.on_message(message(plugin, "x", room=FOREIGN))          # a room the bot did not create
    await plugin.on_message(message(plugin, "x", encrypted=False))       # not encrypted on the server
    await plugin.on_message(message(plugin, "x", msgtype="m.notice"))
    await plugin.on_message(message(plugin, "x", extra={"m.relates_to": {"rel_type": "m.replace", "event_id": "$o"}}))
    await plugin.on_message(message(plugin, "   "))
    assert (await call(client, "/events", {}))[1]["events"] == []


async def test_too_long_message_gets_a_notice(setup):
    plugin, client = setup
    await plugin.on_message(message(plugin, "x" * (core.INBOUND_MAX + 1)))
    assert len(plugin.inbox.items) == 0
    assert plugin.client.sent[-1][2]["msgtype"] == "m.notice"


async def test_events_waits_and_wakes(setup):
    plugin, client = setup
    waiting = asyncio.ensure_future(call(client, "/events", {"wait": 10}))
    await asyncio.sleep(0.2)
    assert not waiting.done()
    await plugin.on_message(message(plugin, "wake"))
    status, body, signed = await asyncio.wait_for(waiting, 3)
    assert [e["text"] for e in body["events"]] == ["wake"] and signed


async def test_wrong_secret_and_replay(setup):
    plugin, client = setup
    status, body, signed = await call(client, "/send", {"room": CONTROL, "text": "x"}, secret="x" * 40)
    assert (status, body, signed) == (401, {"error": "bad signature"}, False)
    assert plugin.client.sent == []
    data = json.dumps({"wait": 0}).encode()
    headers = core.sign_request(SECRET.encode(), "POST", "/events", data)
    first = await client.post(PREFIX + "/events", data=data, headers=headers)
    second = await client.post(PREFIX + "/events", data=data, headers=headers)
    assert first.status == 200 and second.status == 401


async def test_no_secret(setup):
    plugin, client = setup
    plugin.config["secret"] = "short"
    status, _, signed = await call(client, "/send", {"room": CONTROL, "text": "x"})
    assert (status, signed) == (503, False)


async def test_send_and_edit(setup):
    plugin, client = setup
    assert await call(client, "/send", {"room": SESSION, "text": "<b>hi</b>"}) == (201, {"event": "$ev1"}, True)
    content = plugin.client.sent[0][2]
    assert content["body"] == "<b>hi</b>" and "formatted_body" not in content
    assert await call(client, "/edit", {"room": SESSION, "event": "$ev1", "text": "new"}) == (200, {"event": "$ev2"}, True)
    assert plugin.client.sent[1][2]["m.relates_to"] == {"rel_type": "m.replace", "event_id": "$ev1"}
    status, body, signed = await call(client, "/send", {"room": FOREIGN, "text": "x"})
    assert (status, body["error"]) == (403, "not a room of this plugin")
    assert len(plugin.client.sent) == 2


async def test_room_is_encrypted_and_owner_invited(setup):
    plugin, client = setup
    assert await call(client, "/room", {"name": "local/x"}) == (201, {"room": "!new:example.org"}, True)
    made = plugin.client.created[0]
    assert made["invitees"] == [OWNER] and made["name"] == "local/x"
    assert made["initial_state"][0]["type"] == "m.room.encryption"
    # The new room is one of ours without asking the server.
    assert (await call(client, "/send", {"room": "!new:example.org", "text": "x"}))[0] == 201


async def test_archive(setup):
    plugin, client = setup
    assert await call(client, "/archive", {"room": SESSION, "name": "[ended] x"}) == (200, {"archived": True}, True)
    assert plugin.client.left == [SESSION] and plugin.client.sent[-1][1] == "m.room.name"
    status, body, _ = await call(client, "/archive", {"room": CONTROL, "name": "x"})
    assert status == 403 and plugin.client.left == [SESSION]
    assert (await call(client, "/archive", {"room": FOREIGN, "name": "x"}))[0] == 403


async def test_matrix_failure_is_signed_502(setup):
    plugin, client = setup

    async def fail(room, content):
        raise RuntimeError("no")

    plugin.client.send_message = fail
    status, body, signed = await call(client, "/send", {"room": SESSION, "text": "x"})
    assert (status, signed) == (502, True)
