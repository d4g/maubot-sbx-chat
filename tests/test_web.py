"""The HTTP endpoints and the message handler of the real plugin class, with a fake Matrix client.

Needs maubot (skipped without it): uv run --no-project --python 3.13 --with maubot==0.6.0 --with pytest
--with pytest-aiohttp pytest tests
"""
import asyncio
import base64
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
from mautrix.crypto.attachments import encrypt_attachment  # noqa: E402
from mautrix.types import Event, EventType, MemberStateEventContent, Membership  # noqa: E402

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
        # (space, child room) -> content of the m.space.child as the server holds it; absent = never set (a real 404).
        self.children = {}

    async def request(self, method, path, **kwargs):
        parts = [urllib.parse.unquote(p) for p in str(path).split("/")]
        if "m.space.child" in parts:
            return self.children[(parts[parts.index("rooms") + 1], parts[-1])]
        return self.stored[parts[-1]]


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
        self.sent, self.created, self.left, self.state_keys, self.uploads = [], [], [], [], []
        self.spaces_made = 0
        self.api, self.crypto = FakeApi(), FakeCrypto()
        self.files = {}
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

    async def send_state_event(self, room, event_type, content, state_key=""):
        # As maubot's client does after the PUT: a member event's content is read as an object (`.membership`), so a dict
        # fails here, after the server has applied the change (the real failure of 2026-11-11).
        if event_type == EventType.ROOM_MEMBER and not isinstance(content, MemberStateEventContent):
            raise AttributeError("'dict' object has no attribute 'membership'")
        if hasattr(content, "serialize"):
            content = content.serialize()
            content.pop("is_direct", None)             # the default of MemberStateEventContent, not what the tests are about
        self.sent.append((room, str(event_type), content))
        self.state_keys.append(state_key)
        if str(event_type) == "m.space.child":
            if content:
                self.api.children[(room, state_key)] = content
            else:
                self.api.children.pop((room, state_key), None)     # a real server keeps an empty event; same for has_link
        return "$state"

    async def create_room(self, **kwargs):
        self.created.append(kwargs)
        if (kwargs.get("creation_content") or {}).get("type") == "m.space":
            self.spaces_made += 1
            return f"!space{self.spaces_made}:example.org"
        return "!new:example.org"

    async def upload_media(self, data, mime_type=None, filename=None):
        self.uploads.append((bytes(data), mime_type, filename))
        return f"mxc://example.org/up{len(self.uploads)}"

    async def download_media(self, url):
        return self.files[url]

    async def leave_room(self, room):
        self.left.append(room)


class FakeConfig:
    """What the plugin uses of maubot's BaseProxyConfig: dotted keys, and save() (counted)."""

    def __init__(self, **values):
        self.values, self.saves = dict(values), 0

    def __getitem__(self, key):
        return self.values.get(key)

    def __setitem__(self, key, value):
        self.values[key] = value

    def save(self):
        self.saves += 1


APPROVAL = "!approval:example.org"


def make_plugin():
    plugin = object.__new__(sbx_chat.SbxChat)
    plugin.config = FakeConfig(owner=OWNER, room_id=CONTROL, secret=SECRET, approval_room=APPROVAL)
    plugin.spaces_lock = asyncio.Lock()
    plugin.linked = set()
    plugin.client = FakeClient()
    plugin.log = logging.getLogger("test")
    plugin.nonces = core.Nonces()
    plugin.inbox = core.Inbox()
    plugin.media = core.MediaStore()
    plugin.fresh = asyncio.Condition()
    plugin.own_rooms = {}
    plugin.awaiting = {}
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
    # The new room is one of ours without asking the server (a send is accepted, held until the owner joins).
    assert (await call(client, "/send", {"room": "!new:example.org", "text": "x"}))[0] == 202


async def test_archive(setup):
    plugin, client = setup
    assert await call(client, "/archive", {"room": SESSION, "name": "[ended] x"}) == (200, {"archived": True}, True)
    assert plugin.client.left == [SESSION] and plugin.client.sent[-1][1] == "m.room.name"
    status, body, _ = await call(client, "/archive", {"room": CONTROL, "name": "x"})
    assert status == 403 and plugin.client.left == [SESSION]
    assert (await call(client, "/archive", {"room": FOREIGN, "name": "x"}))[0] == 403


async def test_nick_sets_the_bots_own_member_event_and_keeps_the_avatar(setup):
    plugin, client = setup
    plugin.client.api.stored[BOT] = {"membership": "join", "displayname": "old", "avatar_url": "mxc://example.org/a", "reason": "x"}
    assert await call(client, "/nick", {"room": SESSION, "name": " Mira "}) == (200, {"nick": "Mira"}, True)
    assert plugin.client.sent[-1] == (SESSION, "m.room.member", {"membership": "join", "displayname": "Mira",
                                                                  "avatar_url": "mxc://example.org/a"})
    assert plugin.client.state_keys == [BOT]                      # the bot's own event, never somebody else's


async def test_nick_without_a_readable_member_event_sends_no_avatar(setup):
    plugin, client = setup
    assert (await call(client, "/nick", {"room": SESSION, "name": "Mira"}))[0] == 200
    assert plugin.client.sent[-1][2] == {"membership": "join", "displayname": "Mira"}


async def test_nick_refusals(setup):
    plugin, client = setup
    assert (await call(client, "/nick", {"room": CONTROL, "name": "x"}))[0] == 403
    assert (await call(client, "/nick", {"room": FOREIGN, "name": "x"}))[0] == 403
    for bad in ({"room": SESSION}, {"room": SESSION, "name": "  "}, {"room": SESSION, "name": "a\nb"},
                {"room": SESSION, "name": "x" * (core.NAME_MAX + 1)}, {"name": "x"}):
        assert (await call(client, "/nick", bad))[0] == 400, bad
    assert plugin.client.state_keys == []


AVATAR_PNG = b"\x89PNG\r\n\x1a\n" + b"x" * 100


def b64png(data=AVATAR_PNG):
    return base64.b64encode(data).decode()


async def test_avatar_uploads_the_png_and_sets_it_on_the_bots_member_event_keeping_the_name(setup):
    plugin, client = setup
    plugin.client.api.stored[BOT] = {"membership": "join", "displayname": "Mira", "avatar_url": "mxc://example.org/old"}
    assert await call(client, "/avatar", {"room": SESSION, "data": b64png()}) == (200, {"avatar": True}, True)
    assert plugin.client.uploads == [(AVATAR_PNG, "image/png", "avatar.png")]
    assert plugin.client.sent[-1] == (SESSION, "m.room.member", {"membership": "join", "displayname": "Mira",
                                                                  "avatar_url": "mxc://example.org/up1"})
    assert plugin.client.state_keys == [BOT]


async def test_avatar_with_empty_data_removes_the_picture_and_keeps_the_name(setup):
    plugin, client = setup
    plugin.client.api.stored[BOT] = {"membership": "join", "displayname": "Mira", "avatar_url": "mxc://example.org/old"}
    assert await call(client, "/avatar", {"room": SESSION, "data": ""}) == (200, {"avatar": False}, True)
    assert plugin.client.uploads == []
    assert plugin.client.sent[-1][2] == {"membership": "join", "displayname": "Mira"}


async def test_nick_keeps_the_picture_after_this_change(setup):
    plugin, client = setup
    plugin.client.api.stored[BOT] = {"membership": "join", "displayname": "old", "avatar_url": "mxc://example.org/a"}
    assert (await call(client, "/nick", {"room": SESSION, "name": "Ann"}))[0] == 200
    assert plugin.client.sent[-1][2] == {"membership": "join", "displayname": "Ann", "avatar_url": "mxc://example.org/a"}


async def test_roomicon_uploads_and_sets_m_room_avatar(setup):
    plugin, client = setup
    assert await call(client, "/roomicon", {"room": SESSION, "data": b64png()}) == (200, {"icon": True}, True)
    assert plugin.client.uploads == [(AVATAR_PNG, "image/png", "icon.png")]
    assert plugin.client.sent[-1] == (SESSION, "m.room.avatar", {"url": "mxc://example.org/up1"})
    assert plugin.client.state_keys == [""]


async def test_picture_refusals(setup):
    plugin, client = setup
    big = b64png(b"\x89PNG\r\n\x1a\n" + b"x" * core.AVATAR_MAX)
    for path in ("/avatar", "/roomicon"):
        assert (await call(client, path, {"room": CONTROL, "data": b64png()}))[0] == 403
        assert (await call(client, path, {"room": FOREIGN, "data": b64png()}))[0] == 403
        assert (await call(client, path, {"room": SESSION, "data": b64png(b"not a png at all")}))[0] == 400
        assert (await call(client, path, {"room": SESSION, "data": "%%%"}))[0] == 400
        assert (await call(client, path, {"room": SESSION}))[0] == 400
        assert (await call(client, path, {"room": SESSION, "data": big}))[0] == 413
    assert (await call(client, "/roomicon", {"room": SESSION, "data": ""}))[0] == 400      # no way to remove an icon here
    assert plugin.client.uploads == [] and plugin.client.state_keys == []


async def test_send_in_a_thread_and_the_plain_send_is_unchanged(setup):
    plugin, client = setup
    status, body, signed = await call(client, "/send", {"room": SESSION, "text": "thinking...", "thread": "$answer:example.org"})
    assert (status, signed) == (201, True) and body["thread"] == "$answer:example.org"
    assert plugin.client.sent[-1] == (SESSION, "m.room.message", {
        "msgtype": "m.text", "body": "thinking...",
        "m.relates_to": {"rel_type": "m.thread", "event_id": "$answer:example.org", "is_falling_back": True,
                         "m.in_reply_to": {"event_id": "$answer:example.org"}}})
    status, body, _ = await call(client, "/send", {"room": SESSION, "text": "plain"})
    assert status == 201 and "thread" not in body and plugin.client.sent[-1][2]["body"] == "plain"
    assert "m.relates_to" not in plugin.client.sent[-1][2]


async def test_send_refuses_a_bad_thread_and_a_foreign_room(setup):
    plugin, client = setup
    for bad in ("answer", "$a b", 5, ""):
        assert (await call(client, "/send", {"room": SESSION, "text": "x", "thread": bad}))[0] == 400, bad
    assert (await call(client, "/send", {"room": FOREIGN, "text": "x", "thread": "$a:b"}))[0] == 403


async def test_matrix_failure_is_signed_502(setup):
    plugin, client = setup

    async def fail(room, content):
        raise RuntimeError("no")

    plugin.client.send_message = fail
    status, body, signed = await call(client, "/send", {"room": SESSION, "text": "x"})
    assert (status, signed) == (502, True)


# --- images -------------------------------------------------------------------------------------------------------

PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4


def image(plugin, data=PNG, mime="image/png", room=SESSION, sender=OWNER, caption=None, size=None, plain_url=False,
          msgtype="m.image", info=True):
    """An m.image whose attachment is encrypted as a client does it and held by the fake media repository."""
    cipher, enc = encrypt_attachment(data)
    url = f"mxc://example.org/{next(_counter)}"
    plugin.client.files[url] = cipher
    extra = {"filename": "photo.png", "info": {"mimetype": mime, "size": len(data) if size is None else size}}
    if not info:
        del extra["info"]
    if plain_url:
        extra["url"] = url
    else:
        extra["file"] = dict(enc.serialize(), url=url)
    return message(plugin, caption if caption is not None else "photo.png", room=room, sender=sender, msgtype=msgtype,
                   extra=extra)


async def events(client):
    return (await call(client, "/events", {"wait": 0}))[1]["events"]


async def test_encrypted_image_round_trip_and_served_once(setup):
    plugin, client = setup
    await plugin.on_message(image(plugin))
    [item] = await events(client)
    assert item["room"] == SESSION and item["text"] == "" and item["image"]["mime"] == "image/png"
    assert item["image"]["size"] == len(PNG)
    status, body, signed = await call(client, "/media", {"id": item["image"]["id"]})
    assert (status, signed, body["mime"]) == (200, True, "image/png")
    assert base64.b64decode(body["data"]) == PNG
    status, body, signed = await call(client, "/media", {"id": item["image"]["id"]})
    assert (status, signed) == (404, True) and len(plugin.media) == 0


async def test_caption_follows_the_filename_convention(setup):
    plugin, client = setup
    await plugin.on_message(image(plugin, caption="what is this?"))
    await plugin.on_message(image(plugin))
    assert [e["text"] for e in await events(client)] == ["what is this?", ""]


async def test_image_refusals_give_notices(setup):
    plugin, client = setup
    big = core.IMAGE_MAX + 1
    await plugin.on_message(image(plugin, size=big))                       # announced too large
    await plugin.on_message(image(plugin, data=b"x" * big))                # announced small, really large
    await plugin.on_message(image(plugin, mime="image/svg+xml"))
    await plugin.on_message(image(plugin, plain_url=True))                 # not an encrypted attachment
    await plugin.on_message(image(plugin, info=False))
    await plugin.on_message(image(plugin, room=CONTROL))
    assert await events(client) == [] and len(plugin.media) == 0
    texts = [c[2]["body"] for c in plugin.client.sent]
    assert len(texts) == 6 and all(c[2]["msgtype"] == "m.notice" for c in plugin.client.sent)
    assert "Images go into a session room." in texts[-1] and "Only text and images" in texts[2]
    assert "not sent as an encrypted attachment" in texts[3]


async def test_image_of_a_corrupt_attachment_is_refused(setup):
    plugin, client = setup
    evt = image(plugin)
    url = next(iter(plugin.client.files))
    plugin.client.files[url] = plugin.client.files[url][:-1] + b"\x00"    # hash mismatch
    await plugin.on_message(evt)
    assert await events(client) == [] and "decrypted" in plugin.client.sent[-1][2]["body"]


async def test_image_from_others_or_unencrypted_is_ignored(setup):
    plugin, client = setup
    await plugin.on_message(image(plugin, sender="@other:example.org"))
    await plugin.on_message(image(plugin, room=FOREIGN))
    assert await events(client) == [] and plugin.client.sent == []


async def test_unsupported_message_types_get_a_notice(setup):
    plugin, client = setup
    for msgtype in ("m.file", "m.audio", "m.video"):
        await plugin.on_message(message(plugin, "x", msgtype=msgtype))
    await plugin.on_message(message(plugin, "x", msgtype="m.notice"))
    await plugin.on_message(message(plugin, "x", extra={"m.relates_to": {"rel_type": "m.replace", "event_id": "$o"}}))
    assert len(plugin.client.sent) == 3 and "Only text and images" in plugin.client.sent[0][2]["body"]


async def test_media_needs_a_signature_and_a_valid_id(setup):
    plugin, client = setup
    await plugin.on_message(image(plugin))
    key = (await events(client))[0]["image"]["id"]
    status, body, signed = await call(client, "/media", {"id": key}, secret="x" * 40)
    assert (status, signed) == (401, False) and len(plugin.media) == 1
    assert (await call(client, "/media", {"id": "../x"}))[0] == 400
    assert (await call(client, "/media", {}))[0] == 400
    assert len(plugin.media) == 1


async def test_a_large_valid_picture_arrives_whole(setup):
    """The body is read to its end: a 1.5 MiB picture is several network chunks, and a cut body would fail its signature."""
    plugin, client = setup
    big = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * (6 * 1024)
    assert (await call(client, "/avatar", {"room": SESSION, "data": base64.b64encode(big).decode()}))[0] == 200
    assert plugin.client.uploads[-1][0] == big


async def test_send_into_a_new_room_is_held_until_the_owner_joins(setup):
    """The first notice of the daemon went out before the owner had joined and was unreadable for him."""
    plugin, client = setup
    room = "!new:example.org"
    plugin.client.creators[room] = BOT
    assert (await call(client, "/room", {"name": "local/x"}))[0] == 201
    status, body, signed = await call(client, "/send", {"room": room, "text": "Session local/x"})
    assert (status, body, signed) == (202, {"event": None, "held": True}, True)
    await call(client, "/send", {"room": room, "text": "second"})
    assert plugin.client.sent == []                                   # nothing sent while the owner is only invited
    await plugin.on_member(member(room, OWNER, Membership.INVITE, sender=BOT))
    assert plugin.client.sent == []
    await plugin.on_member(member(room, OWNER, Membership.JOIN))
    assert plugin.client.crypto.crypto_store.dropped == [room]        # the new session first ...
    assert [c[2]["body"] for c in plugin.client.sent] == ["Session local/x", "second"]   # ... then the held texts, in order
    assert (await call(client, "/send", {"room": room, "text": "later"}))[0] == 201     # afterwards sends go out at once
    await plugin.on_member(member(room, OWNER, Membership.JOIN))      # a second join event sends nothing again
    assert len(plugin.client.sent) == 3


async def test_held_messages_expire_when_the_owner_never_joins(setup):
    plugin, client = setup
    room = "!new:example.org"
    await call(client, "/room", {"name": "local/x"})
    await call(client, "/send", {"room": room, "text": "held"})
    plugin.awaiting[room][0] -= sbx_chat.HOLD_MAX + 1
    assert (await call(client, "/send", {"room": room, "text": "now"}))[0] == 201
    assert [c[2]["body"] for c in plugin.client.sent] == ["now"] and room not in plugin.awaiting


async def test_archive_forgets_held_messages(setup):
    plugin, client = setup
    room = "!new:example.org"
    plugin.client.creators[room] = BOT
    await call(client, "/room", {"name": "local/x"})
    await call(client, "/send", {"room": room, "text": "held"})
    await call(client, "/archive", {"room": room, "name": "[ended] x"})
    assert room not in plugin.awaiting


async def test_a_thread_reply_is_not_held_for_the_owner(setup):
    """A reply in a thread answers a message of this account, so it is sent at once even while the owner has not joined."""
    plugin, client = setup
    room = "!new:example.org"
    plugin.client.creators[room] = BOT
    await call(client, "/room", {"name": "local/x"})
    status, body, signed = await call(client, "/send", {"room": room, "text": "t", "thread": "$answer:example.org"})
    assert (status, signed) == (201, True) and body["thread"] == "$answer:example.org"
    assert plugin.client.sent[-1][2]["body"] == "t" and plugin.awaiting[room][1] == []


# --- spaces -------------------------------------------------------------------------------------------------------


def children(plugin, space):
    """The rooms the (fake) server lists as live children of a space."""
    return sorted(room for (sp, room) in plugin.client.api.children if sp == space)


async def test_the_spaces_are_made_once_and_saved(setup):
    plugin, client = setup
    assert (await call(client, "/place", {"room": SESSION, "space": "dev"}))[:2] == (200, {"space": "dev"})
    made = plugin.client.created
    assert [m["name"] for m in made] == ["Agent sandbox", "Dev", "Orchestrator", "Rollenspiel"]
    parent = plugin.config["spaces.parent"]
    assert parent == "!space1:example.org" and plugin.config["spaces.rp"] == "!space4:example.org"
    assert plugin.config.saves == 4                       # saved after every space, not once at the end
    for m in made:
        assert m["creation_content"] == {"type": "m.space"} and m["invitees"] == [OWNER] and m["is_direct"] is False
        assert "preset" not in m                          # create_room's default: private, invite only
        assert m["power_level_override"]["users"] == {BOT: 100, OWNER: 100}
        assert not any(e["type"] == "m.room.encryption" for e in m["initial_state"])    # spaces carry no messages
    assert made[0]["initial_state"] == []                 # the parent has no parent
    assert made[1]["initial_state"] == [{"type": "m.space.parent", "state_key": parent,
                                         "content": {"via": ["example.org"], "canonical": True}}]
    # the parent holds the three sub-spaces, the control room and the approval room; Dev holds the placed session
    assert children(plugin, parent) == sorted(["!space2:example.org", "!space3:example.org", "!space4:example.org",
                                               CONTROL, APPROVAL])
    assert children(plugin, "!space2:example.org") == [SESSION]
    assert plugin.client.api.children[(parent, CONTROL)] == {"via": ["example.org"]}
    # a second request, and a restart (a new plugin object over the same config and server), make nothing new
    await call(client, "/place", {"room": SESSION, "space": "dev"})
    assert plugin.client.spaces_made == 4
    again = make_plugin()
    again.client, again.config = plugin.client, plugin.config
    await again._ensure_spaces()
    assert plugin.client.spaces_made == 4 and plugin.config.saves == 4


async def test_a_crash_between_two_spaces_does_not_make_a_second_copy(setup):
    plugin, client = setup
    real = plugin.client.create_room
    calls = []

    async def die_on_third(**kwargs):
        calls.append(kwargs["name"])
        if len(calls) == 3:
            raise RuntimeError("homeserver gone")
        return await real(**kwargs)

    plugin.client.create_room = die_on_third
    assert (await call(client, "/place", {"room": SESSION, "space": "dev"}))[0] == 502
    assert plugin.config["spaces.parent"] and plugin.config["spaces.dev"] and not plugin.config["spaces.orchestrator"]
    plugin.client.create_room = real
    assert (await call(client, "/place", {"room": SESSION, "space": "dev"}))[0] == 200
    assert plugin.client.spaces_made == 4                 # parent, dev, then orchestrator and rp: four in all, none twice


async def test_room_without_space_is_unchanged(setup):
    plugin, client = setup
    assert await call(client, "/room", {"name": "local/x"}) == (201, {"room": "!new:example.org"}, True)
    assert plugin.client.created[0]["initial_state"] == [sbx_chat.ENCRYPTION] and plugin.client.spaces_made == 0


async def test_room_with_space_claims_the_parent_and_is_listed(setup):
    plugin, client = setup
    assert await call(client, "/room", {"name": "rp/x", "space": "rp"}) == (
        201, {"room": "!new:example.org", "space": "rp"}, True)
    rp = plugin.config["spaces.rp"]
    session = [c for c in plugin.client.created if c["name"] == "rp/x"][0]
    assert session["initial_state"][0]["type"] == "m.room.encryption"
    assert session["initial_state"][1] == {"type": "m.space.parent", "state_key": rp,
                                           "content": {"via": ["example.org"], "canonical": True}}
    assert children(plugin, rp) == ["!new:example.org"]
    assert (await call(client, "/send", {"room": "!new:example.org", "text": "x"}))[0] == 202   # still held for the join


async def test_room_with_a_bad_space_is_refused(setup):
    plugin, client = setup
    for bad in ("other", "", 3, ["dev"], "parent"):
        assert (await call(client, "/room", {"name": "x", "space": bad}))[0] == 400
    assert plugin.client.created == []


async def test_a_failing_space_never_fails_the_room(setup):
    plugin, client = setup
    real = plugin.client.create_room

    async def no_spaces(**kwargs):
        if kwargs.get("creation_content"):
            raise RuntimeError("no")
        return await real(**kwargs)

    plugin.client.create_room = no_spaces
    status, body, signed = await call(client, "/room", {"name": "local/x", "space": "dev"})
    assert (status, body, signed) == (201, {"room": "!new:example.org", "space": None}, True)
    assert [e["type"] for e in plugin.client.created[-1]["initial_state"]] == ["m.room.encryption"]
    # and when only the listing fails: the room is made with its parent claim, the answer says it is not listed
    plugin.client.create_room = real
    send = plugin.client.send_state_event

    async def refuse_children(room, event_type, content, state_key=""):
        if str(event_type) == "m.space.child" and state_key == "!new:example.org":
            raise RuntimeError("no power")
        return await send(room, event_type, content, state_key)

    plugin.client.send_state_event = refuse_children
    assert (await call(client, "/room", {"name": "local/y", "space": "dev"}))[1]["space"] is None


async def test_place_is_idempotent_and_sends_no_event_for_a_live_link(setup):
    plugin, client = setup
    assert (await call(client, "/place", {"room": SESSION, "space": "orchestrator"}))[1] == {"space": "orchestrator"}
    sent = len(plugin.client.sent)
    plugin.linked.clear()                                 # as after a restart: the state is read, not remembered
    assert (await call(client, "/place", {"room": SESSION, "space": "orchestrator"}))[0] == 200
    assert len(plugin.client.sent) == sent and children(plugin, plugin.config["spaces.orchestrator"]) == [SESSION]


async def test_place_refusals(setup):
    plugin, client = setup
    assert (await call(client, "/place", {"room": FOREIGN, "space": "dev"}))[0] == 403
    assert (await call(client, "/place", {"room": SESSION, "space": "nope"}))[0] == 400
    assert (await call(client, "/place", {"room": SESSION}))[0] == 400
    assert (await call(client, "/place", {"space": "dev"}))[0] == 400
    assert plugin.client.created == []


async def test_an_unset_approval_room_is_skipped(setup):
    plugin, client = setup
    plugin.config["approval_room"] = ""
    await call(client, "/place", {"room": SESSION, "space": "dev"})
    assert APPROVAL not in children(plugin, plugin.config["spaces.parent"])


async def test_archive_takes_the_room_out_of_its_space(setup):
    plugin, client = setup
    await call(client, "/place", {"room": SESSION, "space": "dev"})
    dev, rp = plugin.config["spaces.dev"], plugin.config["spaces.rp"]
    assert children(plugin, dev) == [SESSION]
    plugin.client.sent.clear(), plugin.client.state_keys.clear()
    assert (await call(client, "/archive", {"room": SESSION, "name": "[ended] x"}))[:2] == (200, {"archived": True})
    assert children(plugin, dev) == [] and plugin.client.left == [SESSION]
    assert (dev, "m.space.child", {}) in plugin.client.sent
    assert (SESSION, "m.space.parent", {}) in plugin.client.sent and dev in plugin.client.state_keys
    assert not any(r == rp for r, _, _ in plugin.client.sent)     # the other sub-spaces were not touched
    # a room that is in no space: archived as before, nothing sent into a space
    plugin.client.sent.clear()
    plugin.client.creators["!other:example.org"] = BOT
    await call(client, "/archive", {"room": "!other:example.org", "name": "x"})
    assert [t for _, t, _ in plugin.client.sent] == ["m.room.name"]


async def test_archive_works_when_the_space_is_unreachable(setup):
    plugin, client = setup
    await call(client, "/place", {"room": SESSION, "space": "dev"})
    send = plugin.client.send_state_event

    async def fail_space(room, event_type, content, state_key=""):
        if str(event_type) in ("m.space.child", "m.space.parent"):
            raise RuntimeError("no")
        return await send(room, event_type, content, state_key)

    plugin.client.send_state_event = fail_space
    assert (await call(client, "/archive", {"room": SESSION, "name": "[ended] x"}))[:2] == (200, {"archived": True})
    assert plugin.client.left == [SESSION]


async def test_the_control_room_and_the_approval_room_are_in_the_parent_space(setup):
    plugin, client = setup
    await plugin._ensure_spaces()
    parent = plugin.config["spaces.parent"]
    assert {CONTROL, APPROVAL} <= set(children(plugin, parent))


async def test_two_requests_at_once_make_the_spaces_once(setup):
    plugin, client = setup
    answers = await asyncio.gather(*[call(client, "/place", {"room": SESSION, "space": key})
                                     for key in ("dev", "orchestrator", "rp", "dev")])
    assert [a[0] for a in answers] == [200] * 4 and plugin.client.spaces_made == 4
