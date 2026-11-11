"""maubot glue of sbx-chat: the HTTP endpoints for sbx-chat on VM 130, and the owner's messages as events.
Logic in core.py. The plugin keeps no session state: VM 130 owns the mapping of rooms to sessions."""
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
from mautrix.types import EncryptedEvent, Event, EventType, Membership, MessageType, TextMessageEventContent
from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper

from . import core

# The largest request: a text of core.TEXT_MAX plus the JSON around it.
BODY_MAX = core.TEXT_MAX + 4 * 1024
UNSUPPORTED = "Only text and images (PNG, JPEG, WebP, GIF, up to 10 MiB) are supported."
ENCRYPTION = {"type": "m.room.encryption", "state_key": "", "content": {"algorithm": "m.megolm.v1.aes-sha2"}}


class Config(BaseProxyConfig):
    def do_update(self, helper: ConfigUpdateHelper) -> None:
        for key in ("owner", "room_id", "secret"):
            helper.copy(key)


class SbxChat(Plugin):
    nonces: core.Nonces
    inbox: core.Inbox
    media: core.MediaStore
    fresh: asyncio.Condition
    # Rooms this account made (or found to have made, after a restart): True or False per room ID.
    own_rooms: dict[str, bool]

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
        if self._secret() is None:
            self.log.warning("secret missing or shorter than %d characters: every request is refused", core.SECRET_MIN)

    def on_external_config_update(self) -> None:
        self.config.load_and_update()

    def _secret(self) -> bytes | None:
        secret = self.config["secret"] or ""
        return secret.encode() if len(secret) >= core.SECRET_MIN else None

    # --- HTTP -------------------------------------------------------------------------------------------------

    async def _read(self, request: Request) -> tuple[str, object]:
        if request.content_length is not None and request.content_length > BODY_MAX:
            raise core.Refused(413, "body too large")
        body = await request.content.read(BODY_MAX + 1)
        if len(body) > BODY_MAX:
            raise core.Refused(413, "body too large")
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
        try:
            nonce, data = await self._read(request)
            room, text = core.parse_send(data)
            await self._need_room(room)
            event_id = await self.client.send_message(room, _message(text))
            return self._reply(nonce, 201, {"event": event_id})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("send failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not send"})

    @web.post("/edit")
    async def edit(self, request: Request) -> Response:
        try:
            nonce, data = await self._read(request)
            room, event_id, text = core.parse_edit(data)
            await self._need_room(room)
            edit_id = await self.client.send_message_event(room, EventType.ROOM_MESSAGE,
                                                           core.edit_content(event_id, text))
            return self._reply(nonce, 200, {"event": edit_id})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("edit failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not edit"})

    @web.post("/room")
    async def room(self, request: Request) -> Response:
        """An end-to-end encrypted private room with the owner invited. Encryption is part of the creation, so no
        message can ever be sent into the room unencrypted."""
        try:
            nonce, data = await self._read(request)
            name = core.parse_room(data)
            room_id = await self.client.create_room(name=name, invitees=[self.config["owner"]], is_direct=False,
                                                    initial_state=[ENCRYPTION])
            self.own_rooms[room_id] = True
            return self._reply(nonce, 201, {"room": room_id})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("room creation failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not create the room"})

    @web.post("/archive")
    async def archive(self, request: Request) -> Response:
        """Rename a session room, then leave it. The owner keeps the room and its history; the bot does not."""
        try:
            nonce, data = await self._read(request)
            room, name = core.parse_archive(data)
            if room == self.config["room_id"]:
                raise core.Refused(403, "the control room is never archived")
            await self._need_room(room)
            await self.client.send_state_event(room, EventType.ROOM_NAME, {"name": name})
            await self.client.leave_room(room)
            self.own_rooms.pop(room, None)
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
            content = {"membership": "join", "displayname": name}
            avatar = (await self._own_member(room)).get("avatar_url")
            if isinstance(avatar, str):
                content["avatar_url"] = avatar
            await self.client.send_state_event(room, EventType.ROOM_MEMBER, content, state_key=self.client.mxid)
            return self._reply(nonce, 200, {"nick": name})
        except core.Refused as error:
            return self._refused(error)
        except Exception:
            self.log.exception("nick failed")
            return self._reply(await self._nonce_of(request), 502, {"error": "could not set the name"})

    async def _own_member(self, room: str) -> dict:
        """The bot's current member event content in a room, {} if it cannot be read."""
        try:
            content = await self.client.api.request(Method.GET, Path.v3.rooms[room].state["m.room.member"][self.client.mxid])
            return content if isinstance(content, dict) else {}
        except Exception:
            return {}

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
            self.inbox.add(evt.room_id, body, evt.event_id)
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
            self.inbox.add(room, core.caption_of(content), evt.event_id, {"id": key, "mime": mime, "size": len(data)})
            self.fresh.notify_all()

    @event.on(EventType.ROOM_MEMBER)
    async def on_member(self, evt) -> None:
        """The owner joined a room of this plugin: start a new Megolm session, so that the owner can read what follows.

        Why: the bot creates a room and sends into it while the owner is only invited. mautrix then shares the first
        session with the joined members, which is the bot alone, and it keeps that session when an invitation turns
        into a join (mautrix/crypto/machine.py, `ignored_changes`), so every later message would stay unreadable for
        the owner ("Unable to decrypt message"; seen 2026-11-09). Dropping the outbound session makes the next
        message create one that is shared with everybody who has joined by then. What was sent before the join stays
        unreadable: the owner's device never got that key."""
        if evt.state_key != self.config["owner"] or evt.content.membership != Membership.JOIN:
            return
        if evt.sender != evt.state_key or not await self._is_ours(evt.room_id):
            return
        if not self.client.crypto:
            return
        try:
            await self.client.crypto.crypto_store.remove_outbound_group_session(evt.room_id)
        except Exception:
            self.log.exception("could not drop the group session of %s", evt.room_id)

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
    """Plain text only: no HTML is built from the agent's text, so nothing in it can become markup."""
    return TextMessageEventContent(msgtype=MessageType.TEXT, body=text)
