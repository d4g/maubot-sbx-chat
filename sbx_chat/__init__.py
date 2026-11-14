"""maubot glue of sbx-chat: the HTTP endpoints for sbx-chat on VM 130, and the owner's messages as events.
Logic in core.py. The plugin keeps no session state: VM 130 owns the mapping of rooms to sessions. The only thing it
remembers itself is the IDs of the Matrix spaces it made (instance config `spaces`), see _ensure_spaces."""
from __future__ import annotations

import asyncio
import base64
import json
import time

from aiohttp.web import Request, Response
from maubot import Plugin
from maubot.handlers import event, web
from mautrix.api import Method, Path
from mautrix.crypto.attachments import decrypt_attachment
from mautrix.types import (EncryptedEvent, Event, EventType, MemberStateEventContent, Membership, MessageType,
                           RoomAvatarStateEventContent, TextMessageEventContent)
from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper

from . import core

# The largest request: a text of core.TEXT_MAX plus the JSON around it.
BODY_MAX = core.TEXT_MAX + 4 * 1024
UNSUPPORTED = "Only text and images (PNG, JPEG, WebP, GIF, up to 10 MiB) are supported."
# How long what the daemon sends into a new room is held back for the owner's join. After that the owner is assumed not
# to come, the held messages are dropped and the room behaves like any other (a send goes out at once).
HOLD_MAX = 24 * 3600
ENCRYPTION = {"type": "m.room.encryption", "state_key": "", "content": {"algorithm": "m.megolm.v1.aes-sha2"}}


def _server_prev_membership(evt) -> Membership | None:
    """The membership before this member event as the server sent it (unsigned.prev_content), or None. Not from
    StateEvent.prev_content: without a previous state that property returns a default content whose membership is
    "leave" (mautrix/types/event/state.py). A lazy-loaded copy of the owner's original join carries that join's own
    previous state ("invite"), so this alone cannot tell a copy from a new join; see on_member."""
    unsigned = getattr(evt, "unsigned", None)
    return getattr(getattr(unsigned, "prev_content", None), "membership", None) or None


def _cached_membership(evt) -> Membership | None:
    """The membership mautrix had cached for this user before the event (unsigned["mautrix_prev_membership"], a Member),
    or None. mautrix's own handler uses it to skip duplicate member events."""
    unsigned = getattr(evt, "unsigned", None)
    try:
        cached = unsigned.get("mautrix_prev_membership") if unsigned is not None else None
    except (AttributeError, TypeError):
        cached = None
    return getattr(cached, "membership", None)


class Config(BaseProxyConfig):
    def do_update(self, helper: ConfigUpdateHelper) -> None:
        for key in ("owner", "room_id", "secret", "approval_room", "spaces.parent", "spaces.dev", "spaces.orchestrator",
                    "spaces.rp", "spaces.admin"):
            helper.copy(key)


class SbxChat(Plugin):
    nonces: core.Nonces
    inbox: core.Inbox
    media: core.MediaStore
    fresh: asyncio.Condition
    # Rooms this account made (or found to have made, after a restart): True or False per room ID.
    own_rooms: dict[str, bool]
    # Rooms made here whose owner has not joined yet: room ID -> [monotonic time of creation, [held texts]]. What is sent
    # before the join cannot be read by the owner (see on_member), so /send holds it here and on_member sends it after.
    # Not persistent: after a plugin restart a send goes out at once.
    awaiting: dict[str, list]
    # Serialises _ensure_spaces: two requests arriving together must not both create the same space.
    spaces_lock: asyncio.Lock
    # (space, room) pairs known to be linked by an m.space.child, so that the start-up pass of the caller (one /place per
    # session) does not read the same state again with every request. Not persistent: after a restart each is read once.
    linked: set[tuple[str, str]]
    # Rooms of this plugin where the owner's join was already handled (the group session dropped once): room ID -> the
    # event ID of that join. A later join event of the owner there is a copy of the same event or a profile change, not a
    # new join. Not persistent: after a restart the first owner join event per room drops the session once more (one
    # extra rotation, harmless).
    owner_joined: dict[str, str]

    @classmethod
    def get_config_class(cls) -> type[BaseProxyConfig]:
        return Config

    async def start(self) -> None:
        self.config.load_and_update()
        self.nonces = core.Nonces()
        self.inbox = core.Inbox()
        self.media = core.MediaStore()
        self.fresh = asyncio.Condition()
        self.own_rooms = {}
        self.awaiting = {}
        self.spaces_lock = asyncio.Lock()
        self.linked = set()
        self.owner_joined = {}
        if self._secret() is None:
            self.log.warning("secret missing or shorter than %d characters: every request is refused", core.SECRET_MIN)

    def on_external_config_update(self) -> None:
        self.config.load_and_update()

    def _secret(self) -> bytes | None:
        secret = self.config["secret"] or ""
        return secret.encode() if len(secret) >= core.SECRET_MIN else None

    # --- HTTP -------------------------------------------------------------------------------------------------

    async def _read(self, request: Request, limit: int = BODY_MAX) -> tuple[str, object]:
        if request.content_length is not None and request.content_length > limit:
            raise core.Refused(413, "body too large")
        # StreamReader.read(n) returns what has arrived so far, not n bytes: a large body (a picture) must be read to its end.
        chunks, total = [], 0
        while True:
            chunk = await request.content.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise core.Refused(413, "body too large")
            chunks.append(chunk)
        body = b"".join(chunks)
        nonce = core.check_request(self._secret(), self.nonces, request.method, request.path, request.headers, body,
                                   time.time())
        try:
            return nonce, json.loads(body)
        except ValueError:
            raise core.Refused(400, "body is not JSON")

    def _reply(self, nonce: str, status: int, data: dict) -> Response:
        body = json.dumps(data, separators=(",", ":")).encode()
        secret = self._secret()
        headers = {"X-Sbx-Mac": core.mac(secret, core.response_message(nonce, status, body))} if secret else {}
        return Response(status=status, body=body, content_type="application/json", headers=headers)

    @staticmethod
    def _refused(error: core.Refused) -> Response:
        # Unsigned on purpose: the caller treats any unsigned answer as a failure of this channel.
        return Response(status=error.status, text=json.dumps({"error": error.message}), content_type="application/json")

    async def _is_ours(self, room: str) -> bool:
        """The control room, or a room this account created. Autojoin is off, so the bot is in no other room unless
        the owner invited it and someone accepted by hand; the creator check keeps even that out."""
        if room == self.config["room_id"]:
            return True
        if room not in self.own_rooms:
            creator = None
            try:
                for state in await self.client.get_state(room):
                    if str(state.type) == "m.room.create":
                        creator = state.sender
            except Exception:
                self.log.exception("could not read the state of %s", room)
                return False
            self.own_rooms[room] = creator == self.client.mxid
        return self.own_rooms[room]

    async def _need_room(self, room: str) -> None:
        if not await self._is_ours(room):
            raise core.Refused(403, "not a room of this plugin")

    @web.post("/events")
    async def events(self, request: Request) -> Response:
        """The owner's messages after the caller's last sequence number; waits up to `wait` seconds for one. POST, not
        GET, because only the body is signed and the parameters must be."""
        try:
            nonce, data = await self._read(request)
            epoch, after, wait = core.parse_events(data)
            deadline = time.monotonic() + wait
            async with self.fresh:
                while True:
                    reply = self.inbox.reply(epoch, after)
                    left = deadline - time.monotonic()
                    if reply["events"] or left <= 0:
                        break
                    try:
                        await asyncio.wait_for(self.fresh.wait(), left)
                    except asyncio.TimeoutError:
                        pass
            return self._reply(nonce, 200, reply)
        except core.Refused as error:
            return self._refused(error)

    @web.post("/media")
    async def media_endpoint(self, request: Request) -> Response:
        """An image queued with an event, base64 in the answer, once: it is removed when served."""
        try:
            nonce, data = await self._read(request)
            found = self.media.take(core.parse_media(data))
            if found is None:
                return self._reply(nonce, 404, {"error": "unknown image"})
            return self._reply(nonce, 200, {"mime": found[0], "data": base64.b64encode(found[1]).decode()})
        except core.Refused as error:
            return self._refused(error)

    @web.post("/send")
    async def send(self, request: Request) -> Response:
        """A message into a room of this plugin. Plain text unless `markdown` is true: then the text also goes out as HTML
        built by core.markdown_html (escaped first, a few closed spans converted), and `body` stays the raw text. `notice`
        true makes it an m.notice (shown dimmed, never notifies) instead of an m.text. `markdown`, `notice` and `thread` are
        repeated in the answer, so that a caller can tell a plugin that knew the field from an older one that ignored it
        (which would have sent the text unformatted, as m.text, or into the main timeline)."""
        try:
            nonce, data = await self._read(request)
            room, text = core.parse_send(data)
            thread = core.parse_thread(data)
            markdown = core.parse_markdown(data)
            notice = core.parse_notice(data)
            await self._need_room(room)
            known = {**({"thread": thread} if thread else {}), **({"markdown": True} if markdown else {}),
                     **({"notice": True} if notice else {})}
            if thread is None and self._hold(room, text, markdown, notice):
                # 202: accepted, sent after the owner's join; there is no event ID yet. A reply in a thread is never held:
                # it answers a message of this account, which the owner can only have read after the join.
                return self._reply(nonce, 202, {"event": None, "held": True, **known})
            if thread is None and not markdown and not notice:
                event_id = await self.client.send_message(room, _message(text))
            else:
                # A reply in the thread of `thread` (a message of this account, e.g. an answer), a formatted message or a
                # notice: built as a dict (plain text unless core.message_content adds the HTML).
                content = core.message_content(text, markdown, notice)
                if thread:
                    content["m.relates_to"] = core.thread_relation(thread)
                event_id = await self.client.send_message_event(room, EventType.ROOM_MESSAGE, content)
            return self._reply(nonce, 201, {"event": event_id, **known})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("send failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not send"})

    @web.post("/typing")
    async def typing(self, request: Request) -> Response:
        """The bot's typing notification in a room of this plugin (`PUT /rooms/{roomId}/typing/{userId}`, mautrix
        `client.set_typing`): `typing` true shows it for `timeout` milliseconds, false ends it at once. It is ephemeral: no event
        in the timeline, nothing to edit or redact, and it ends by itself when the timeout runs out, so a caller that dies
        leaves nothing behind. The caller refreshes it while it works (the spec recommends every 20 to 30 seconds)."""
        try:
            nonce, data = await self._read(request)
            room, timeout = core.parse_typing(data)
            await self._need_room(room)
            await self.client.set_typing(room, timeout)
            return self._reply(nonce, 200, {"typing": timeout > 0})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("typing failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not set typing"})

    @web.post("/edit")
    async def edit(self, request: Request) -> Response:
        """Replace an earlier message of this account (`m.replace`). `markdown` formats the new text as in /send and is
        repeated in the answer when applied."""
        try:
            nonce, data = await self._read(request)
            room, event_id, text = core.parse_edit(data)
            markdown = core.parse_markdown(data)
            await self._need_room(room)
            edit_id = await self.client.send_message_event(room, EventType.ROOM_MESSAGE,
                                                           core.edit_content(event_id, text, markdown))
            return self._reply(nonce, 200, {"event": edit_id, **({"markdown": True} if markdown else {})})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("edit failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not edit"})

    @web.post("/redact")
    async def redact(self, request: Request) -> Response:
        """Redact (remove the content of) one event in a session room: the caller takes back a message, such as the status
        line it posted for a turn. Never in the control room, and only in rooms this plugin made. Whether the homeserver lets
        the bot redact a given event (its own always; the owner's depends on the room's power levels) is the homeserver's
        decision: a refusal there is the signed 502."""
        try:
            nonce, data = await self._read(request)
            room, event_id = core.parse_redact(data)
            if room == self.config["room_id"]:
                raise core.Refused(403, "nothing is redacted in the control room")
            await self._need_room(room)
            await self.client.redact(room, event_id)
            return self._reply(nonce, 200, {"redacted": True})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("redact failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not redact"})

    @web.post("/react")
    async def react(self, request: Request) -> Response:
        """A reaction (`m.reaction`, `m.annotation`) of the bot to one event of a session room, for example the mark the caller
        puts on an answer it replaced. Only in rooms this plugin made, and never in the control room (nothing there is answered
        with a mark). Whether the event exists is the homeserver's business."""
        try:
            nonce, data = await self._read(request)
            room, event_id, key = core.parse_react(data)
            if room == self.config["room_id"]:
                raise core.Refused(403, "no reactions in the control room")
            await self._need_room(room)
            reaction_id = await self.client.send_message_event(
                room, EventType.REACTION, {"m.relates_to": {"rel_type": "m.annotation", "event_id": event_id, "key": key}})
            return self._reply(nonce, 200, {"event": reaction_id})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("react failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not react"})

    @web.post("/room")
    async def room(self, request: Request) -> Response:
        """An end-to-end encrypted private room with the owner invited. Encryption is part of the creation, so no
        message can ever be sent into the room unencrypted.

        With `space` (one of core.SUBSPACES) the room is also put into that sub-space: the new room claims it with an
        m.space.parent in its initial state, and the space lists it with an m.space.child. A failure there never fails the
        request (a session must not depend on how its room is sorted): the room is returned with `"space": null` and the
        reason is logged. The answer repeats `space` so that the caller can tell a plugin that knew the field from an older
        one, which would have ignored it."""
        try:
            nonce, data = await self._read(request)
            name = core.parse_room(data)
            space = core.parse_space(data)
            space_id = None
            if space:
                try:
                    await self._ensure_spaces()
                    space_id = self.config[f"spaces.{space}"] or None
                except Exception:
                    self.log.exception("could not make the spaces; the room is made without one")
            initial_state = [ENCRYPTION]
            if space_id:
                initial_state.append({"type": "m.space.parent", "state_key": space_id,
                                      "content": core.space_link(self._server(), canonical=True)})
            room_id = await self.client.create_room(name=name, invitees=[self.config["owner"]], is_direct=False,
                                                    initial_state=initial_state)
            self.own_rooms[room_id] = True
            self.awaiting[room_id] = [time.monotonic(), []]
            answer = {"room": room_id}
            if space:
                answer["space"] = None
                if space_id:
                    try:
                        await self._add_child(space_id, room_id)
                        answer["space"] = space
                    except Exception:
                        self.log.exception("could not put %s into the space %s", room_id, space)
            return self._reply(nonce, 201, answer)
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("room creation failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not create the room"})

    @web.post("/place")
    async def place(self, request: Request) -> Response:
        """Put a room of this plugin (the control room or one it made) into a sub-space, if it is not in it yet. For rooms
        that exist already: the caller sends every session room it knows when it starts. Only the m.space.child in the space
        is set (the bot has power there); the room's own m.space.parent is left alone, since a room made before the spaces
        existed need not give the bot the power to change it."""
        try:
            nonce, data = await self._read(request)
            room, space = core.parse_place(data)
            await self._need_room(room)
            await self._ensure_spaces()
            await self._add_child(self.config[f"spaces.{space}"], room)
            return self._reply(nonce, 200, {"space": space})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("place failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not place the room"})

    @web.post("/spaces")
    async def spaces(self, request: Request) -> Response:
        """Make the spaces that are missing and link the fixed rooms (control room, approval room, sub-spaces) into the parent,
        without a room to place. The caller sends it once when it starts, so that the layout exists and the control room is
        in it even when there is no session yet (/room and /place would otherwise be the first to make it). The body is an
        empty JSON object; it is signed like every other request."""
        try:
            nonce, _ = await self._read(request)
            await self._ensure_spaces()
            return self._reply(nonce, 200, {"spaces": {key: self.config[f"spaces.{key}"]
                                                       for key in ("parent", *core.SUBSPACES, "admin")}})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("making the spaces failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not make the spaces"})

    @web.post("/archive")
    async def archive(self, request: Request) -> Response:
        """Rename a session room, take it out of its space, then leave it. The owner keeps the room and its history; the
        bot does not."""
        try:
            nonce, data = await self._read(request)
            room, name = core.parse_archive(data)
            if room == self.config["room_id"]:
                raise core.Refused(403, "the control room is never archived")
            await self._need_room(room)
            await self.client.send_state_event(room, EventType.ROOM_NAME, {"name": name})
            await self._unplace(room)
            await self.client.leave_room(room)
            self.own_rooms.pop(room, None)
            self.awaiting.pop(room, None)
            return self._reply(nonce, 200, {"archived": True})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("archive failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not archive"})

    @web.post("/nick")
    async def nick(self, request: Request) -> Response:
        """The bot's own display name in one session room, so that its answers carry the name of the character it plays.
        It is the bot's own member event (a user can set only their own), sent again with the name changed: membership
        and the room's avatar are kept, everything else of the old event is dropped. The control room keeps the bot's name."""
        try:
            nonce, data = await self._read(request)
            room, name = core.parse_nick(data)
            if room == self.config["room_id"]:
                raise core.Refused(403, "the control room keeps the bot's own name")
            await self._need_room(room)
            await self._set_member(room, displayname=name)
            return self._reply(nonce, 200, {"nick": name})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("nick failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not set the name"})

    async def _set_member(self, room: str, **changes: str) -> None:
        """The bot's own member event, sent again with `displayname` and/or `avatar_url` changed (an empty string removes it).
        Whatever else the old event had is dropped; the membership stays join. The content must be a MemberStateEventContent,
        not a dict: after the PUT, maubot's client writes the event into its state store and reads `.membership` from it (a
        dict broke that with an AttributeError after the server had already applied the change; seen 2026-11-11)."""
        old = await self._own_member(room)
        fields = {}
        for key in ("displayname", "avatar_url"):
            value = changes.get(key, old.get(key))
            if isinstance(value, str) and value:
                fields[key] = value
        content = MemberStateEventContent(membership=Membership.JOIN, **fields)
        await self.client.send_state_event(room, EventType.ROOM_MEMBER, content, state_key=self.client.mxid)

    @web.post("/avatar")
    async def avatar(self, request: Request) -> Response:
        """The bot's own picture in one session room: a PNG, uploaded to the homeserver's media repository and set as the
        avatar of the bot's member event (the name stays); an empty `data` removes the picture. The picture is NOT end-to-end
        encrypted: it lies in the media repository, where only the homeserver's admin can delete it."""
        try:
            nonce, data = await self._read(request, core.AVATAR_BODY_MAX)
            room, image = core.parse_avatar(data, clear_ok=True)
            if room == self.config["room_id"]:
                raise core.Refused(403, "the control room keeps the bot's own picture")
            await self._need_room(room)
            url = ""
            if image is not None:
                url = await self.client.upload_media(image, mime_type="image/png", filename="avatar.png")
            await self._set_member(room, avatar_url=str(url))
            return self._reply(nonce, 200, {"avatar": image is not None})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("avatar failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not set the picture"})

    @web.post("/roomicon")
    async def roomicon(self, request: Request) -> Response:
        """The icon of one session room (m.room.avatar): a PNG uploaded like the bot's picture. The bot made the room, so it has
        the power to set it (not checked against a real server). Not encrypted either."""
        try:
            nonce, data = await self._read(request, core.AVATAR_BODY_MAX)
            room, image = core.parse_avatar(data, clear_ok=False)
            if room == self.config["room_id"]:
                raise core.Refused(403, "the control room keeps its icon")
            await self._need_room(room)
            url = await self.client.upload_media(image, mime_type="image/png", filename="icon.png")
            await self.client.send_state_event(room, EventType.ROOM_AVATAR, RoomAvatarStateEventContent(url=url))
            return self._reply(nonce, 200, {"icon": True})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("room icon failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not set the room icon"})

    # --- spaces -----------------------------------------------------------------------------------------------

    def _server(self) -> str:
        """The homeserver part of the bot's MXID: the `via` of every space link (all rooms here live on that server)."""
        return self.client.mxid.split(":", 1)[1]

    async def _ensure_spaces(self) -> None:
        """Make the spaces that do not exist yet, and link the fixed rooms into the sub-space Admin.

        Layout: the parent space "Agent sandbox" holds three sub-spaces for the session rooms (core.SUBSPACES) and the
        sub-space "Admin" (core.ADMIN_SPACE), which holds the control room and the approval room of sbx-approval (config
        `approval_room`). Until 0.9.0 those two were children of the parent; a live link there is removed, so an existing
        layout moves by itself at the next start. All spaces are private (invite only), not in the room directory,
        and not encrypted: a space carries no messages, only names and links, which the owner's own homeserver sees anyway.
        The owner is invited and gets power level 100 next to the bot, so the owner can move rooms in and out by hand.

        The IDs are the plugin's own state, kept in the instance config (`spaces.*`) and saved after every space made, so a
        crash or restart between two creations cannot make a second copy. A space the owner deleted is not noticed: its ID
        stays in the config until someone empties it there. Linking is best effort (logged, never raised): a bad
        `approval_room` must not keep the session rooms from their space. A failure to make a space is raised."""
        async with self.spaces_lock:
            parent = await self._make_space("parent", core.PARENT_SPACE, None)
            for key, name in core.SUBSPACES.items():
                await self._make_space(key, name, parent)
            admin = await self._make_space("admin", core.ADMIN_SPACE, parent)
            for room in (self.config["room_id"], self.config["approval_room"]):
                if room:
                    try:
                        await self._add_child(admin, room)
                        if (parent, room) in self.linked or await self._child_linked(parent, room):
                            await self._remove_child(parent, room)
                    except Exception:
                        self.log.exception("could not put %s into the space Admin", room)

    async def _make_space(self, key: str, name: str, parent: str | None) -> str:
        """The ID of the space `key` from the config; made, saved and (for a sub-space) linked below `parent` if missing. An
        existing space gets `name` if its name differs (best effort: unreadable or refused is logged and left), so a renamed
        space here (Rollenspiel to RP in 0.9.0) is renamed on the server at the next start."""
        existing = self.config[f"spaces.{key}"]
        if existing:
            try:
                current = await self.client.api.request(Method.GET, Path.v3.rooms[existing].state["m.room.name"][""])
                if isinstance(current, dict) and current.get("name") != name:
                    await self.client.send_state_event(existing, EventType.ROOM_NAME, {"name": name})
                    self.log.info("renamed the space %s to %s", existing, name)
            except Exception:
                self.log.warning("could not check the name of the space %s", key)
            if parent:
                try:
                    await self._add_child(parent, existing)    # a no-op if it is linked; repairs a link lost after a crash
                except Exception:
                    self.log.exception("could not put the space %s into the parent space", key)
            return existing
        owner, bot = self.config["owner"], self.client.mxid
        initial_state = []
        if parent:
            initial_state.append({"type": "m.space.parent", "state_key": parent,
                                  "content": core.space_link(self._server(), canonical=True)})
        # events_default 100: only the owner and the bot may post into a space (nobody should chat there).
        space = await self.client.create_room(
            name=name, invitees=[owner], is_direct=False, initial_state=initial_state,
            creation_content={"type": "m.space"},
            power_level_override={"users": {bot: 100, owner: 100}, "events_default": 100})
        self.config[f"spaces.{key}"] = space
        self.config.save()
        self.log.info("made the space %s (%s)", name, space)
        if parent:
            try:
                await self._add_child(parent, space)
            except Exception:
                self.log.exception("could not put the new space %s into the parent space", key)
        return space

    async def _child_linked(self, space: str, room: str) -> bool:
        """True if `space` has a live m.space.child for `room`. Unreadable (never set: 404) counts as not linked."""
        try:
            content = await self.client.api.request(Method.GET, Path.v3.rooms[space].state["m.space.child"][room])
        except Exception:
            return False
        return core.has_link(content)

    async def _add_child(self, space: str, room: str) -> None:
        """List `room` as a child of `space`. The current state is read first and nothing is sent if the link is live, so
        the start-up pass (one call per existing session) leaves no new events in the space's timeline."""
        if (space, room) in self.linked:
            return
        if not await self._child_linked(space, room):
            await self.client.send_state_event(space, EventType.SPACE_CHILD, core.space_link(self._server()),
                                               state_key=room)
        self.linked.add((space, room))

    async def _remove_child(self, space: str, room: str) -> None:
        """Take `room` out of `space`: an m.space.child with empty content is a removed link (Matrix spec)."""
        await self.client.send_state_event(space, EventType.SPACE_CHILD, {}, state_key=room)
        self.linked.discard((space, room))

    async def _unplace(self, room: str) -> None:
        """Take a room out of every sub-space it is listed in, and withdraw its own m.space.parent claim there (while the bot
        is still a member, so it can). All sub-spaces are checked: the plugin does not record which one a room is in. Every
        failure is logged only: a room must be archivable even when its space is not reachable."""
        for key in core.SUBSPACES:
            space = self.config[f"spaces.{key}"]
            if not space:
                continue
            try:
                if (space, room) not in self.linked and not await self._child_linked(space, room):
                    continue
                await self._remove_child(space, room)
                await self.client.send_state_event(room, EventType.SPACE_PARENT, {}, state_key=space)
            except Exception:
                self.log.exception("could not take %s out of the space %s", room, key)

    async def _own_member(self, room: str) -> dict:
        """The bot's current member event content in a room, {} if it cannot be read."""
        try:
            content = await self.client.api.request(Method.GET, Path.v3.rooms[room].state["m.room.member"][self.client.mxid])
            return content if isinstance(content, dict) else {}
        except Exception:
            return {}

    def _hold(self, room: str, text: str, markdown: bool = False, notice: bool = False) -> bool:
        """True if the text (and whether it is to be formatted, and whether it is a notice) was kept for the owner's join. False if the room is not waiting for the owner, or has waited
        longer than HOLD_MAX: then whatever was held is dropped and the text is sent at once."""
        waiting = self.awaiting.get(room)
        if waiting is None:
            return False
        if time.monotonic() - waiting[0] > HOLD_MAX:
            self.awaiting.pop(room, None)
            self.log.warning("the owner never joined %s: dropped %d held message(s)", room, len(waiting[1]))
            return False
        waiting[1].append((text, markdown, notice))
        return True

    @staticmethod
    async def _nonce_of(request: Request) -> str:
        return request.headers.get("X-Sbx-Nonce", "")

    # --- Matrix -----------------------------------------------------------------------------------------------

    @event.on(EventType.ROOM_MESSAGE)
    async def on_message(self, evt) -> None:
        """A message of the owner in the control room or a session room: queued for sbx-chat to fetch."""
        if evt.sender == self.client.mxid or evt.sender != self.config["owner"]:
            return
        if not await self._is_ours(evt.room_id):
            return
        # maubot hands message events to plugins as a new MaubotMessageEvent that copies only the attrs fields, so the
        # "mautrix" marker decrypt_megolm sets (was_encrypted) is gone here (seen with sbx-approval, 2026-11-07). So
        # fetch the event as stored on the server: it counts only if it is m.room.encrypted there, and then only its
        # own decryption's body counts. A second decryption of the same event passes mautrix's replay check.
        content = await self._decrypted_content(evt.room_id, evt.event_id)
        if content is None or core.is_edit(content):
            return
        msgtype = content.get("msgtype")
        if msgtype == "m.notice":
            return
        if msgtype == "m.image":
            await self._on_image(evt, content)
            return
        if msgtype != "m.text":
            await self._note(evt.room_id, UNSUPPORTED)
            return
        body = content.get("body")
        if not isinstance(body, str) or not body.strip():
            return
        if len(body.encode()) > core.INBOUND_MAX:
            await self._note(evt.room_id, f"Message ignored: longer than {core.INBOUND_MAX // 1024} KiB.")
            return
        async with self.fresh:
            self.inbox.add(evt.room_id, body, evt.event_id, thread=core.thread_of(content))
            self.fresh.notify_all()

    async def _on_image(self, evt, content: dict) -> None:
        """An image in a session room: decrypted here (the attachment is end-to-end encrypted, `content.file`), kept in
        memory, and queued as an event the caller fetches through /media. Every refusal is a notice, never silence."""
        room = evt.room_id
        if room == self.config["room_id"]:
            await self._note(room, "Images go into a session room.")
            return
        file, info = content.get("file"), content.get("info")
        info = info if isinstance(info, dict) else {}
        mime, size = info.get("mimetype"), info.get("size")
        if not isinstance(file, dict) or not isinstance(file.get("url"), str):
            # A plain `url` means the image sits unencrypted on the homeserver: not accepted.
            await self._note(room, "Image ignored: it was not sent as an encrypted attachment.")
            return
        if mime not in core.IMAGE_MIMES:
            await self._note(room, UNSUPPORTED)
            return
        if not isinstance(size, int) or isinstance(size, bool) or size > core.IMAGE_MAX:
            await self._note(room, f"Image ignored: larger than {core.IMAGE_MAX // 1024 // 1024} MiB, or no size given.")
            return
        try:
            cipher = await self.client.download_media(file["url"])
            if len(cipher) > core.IMAGE_MAX:
                await self._note(room, f"Image ignored: larger than {core.IMAGE_MAX // 1024 // 1024} MiB.")
                return
            data = decrypt_attachment(cipher, file["key"]["k"], file["hashes"]["sha256"], file["iv"])
        except Exception:
            self.log.exception("could not fetch or decrypt the image of %s", evt.event_id)
            await self._note(room, "Image ignored: it could not be downloaded or decrypted.")
            return
        key = self.media.put(mime, data)
        async with self.fresh:
            self.inbox.add(room, core.caption_of(content), evt.event_id, {"id": key, "mime": mime, "size": len(data)},
                           core.thread_of(content))
            self.fresh.notify_all()

    @event.on(EventType.ROOM_MEMBER)
    async def on_member(self, evt) -> None:
        """The owner joined a room of this plugin: start a new Megolm session, so that the owner can read what follows.

        Why: the bot creates a room and sends into it while the owner is only invited. mautrix then shares the first
        session with the joined members, which is the bot alone, and it keeps that session when an invitation turns
        into a join (mautrix/crypto/machine.py, `ignored_changes`), so every later message would stay unreadable for
        the owner ("Unable to decrypt message"; seen 2026-11-09). Dropping the outbound session makes the next
        message create one that is shared with everybody who has joined by then. What was sent before the join stays
        unreadable: the owner's device never got that key.

        Only a real join counts, a change from not joined to joined. Before 0.8.1 every join event of the owner dropped
        the session, also a join after a join: the homeserver sends the sender's member event along with the messages
        (lazy-loaded members) and with every profile change. Each answer of the bot then went out under a brand-new
        session whose key was sent milliseconds before it, and Element X showed "Waiting for this message" until the
        room or thread was opened again (seen 2026-11-13). mautrix skips join after join in its own handler too
        (mautrix/crypto/machine.py, handle_member_event)."""
        if evt.state_key != self.config["owner"]:
            return
        if evt.content.membership != Membership.JOIN:
            self.owner_joined.pop(evt.room_id, None)     # left, kicked or banned: a later join is a new one again
            return
        if evt.sender != evt.state_key or not await self._is_ours(evt.room_id):
            return
        event_id = getattr(evt, "event_id", None)
        handled = self.owner_joined.get(evt.room_id)
        if _cached_membership(evt) == Membership.JOIN or (handled is not None and handled == event_id):
            return          # a copy of a join already seen: mautrix's cache knows it, or it is the very event handled
        prev = _server_prev_membership(evt)
        if prev == Membership.JOIN or (handled is not None and prev is None):
            return          # a profile change (join -> join), or a later join event that does not say what came before
        self.owner_joined[evt.room_id] = event_id
        if self.client.crypto:
            try:
                await self.client.crypto.crypto_store.remove_outbound_group_session(evt.room_id)
                self.log.info("owner joined %s: group session dropped, the next message starts a new one", evt.room_id)
            except Exception:
                self.log.exception("could not drop the group session of %s", evt.room_id)
        # Only now, with the new session, can the owner read the notices the daemon sent before the join.
        waiting = self.awaiting.pop(evt.room_id, None)
        for text, markdown, notice in waiting[1] if waiting else []:
            try:
                if markdown or notice:
                    await self.client.send_message_event(evt.room_id, EventType.ROOM_MESSAGE,
                                                         core.message_content(text, markdown, notice))
                else:
                    await self.client.send_message(evt.room_id, _message(text))
            except Exception:
                self.log.exception("could not send a held message to %s", evt.room_id)

    async def _note(self, room: str, text: str) -> None:
        try:
            await self.client.send_message_event(room, EventType.ROOM_MESSAGE, {"msgtype": "m.notice", "body": text})
        except Exception:
            self.log.exception("could not send a notice")

    async def _decrypted_content(self, room_id: str, event_id: str) -> dict | None:
        """The content of an event as decrypted from the server's copy, or None if it was not encrypted or fails."""
        try:
            raw = await self.client.api.request(Method.GET, Path.v3.rooms[room_id].event[event_id])
            stored = Event.deserialize(raw)
            if not isinstance(stored, EncryptedEvent):
                self.log.warning("ignored an unencrypted message %s", event_id)
                return None
            if not self.client.crypto:
                self.log.warning("no crypto in this client: cannot check message %s", event_id)
                return None
            decrypted = await self.client.crypto.decrypt_megolm_event(stored)
        except Exception:
            self.log.exception("could not fetch or decrypt message %s", event_id)
            return None
        content = decrypted.content
        return content.serialize() if hasattr(content, "serialize") else dict(content)


def _message(text: str) -> TextMessageEventContent:
    """Plain text only, the default of /send: no HTML is built unless the caller asks for `markdown` (core.message_content)."""
    return TextMessageEventContent(msgtype=MessageType.TEXT, body=text)
