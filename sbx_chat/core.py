"""The logic of sbx-chat without maubot: request and response signing, request validation, and the inbound queue.

Kept free of maubot and mautrix imports so it can be tested on its own (tests/test_core.py).

Signing is the scheme of maubot-sbx-approval (ADR 0024), unchanged except for the two label lines, so that a signature
made for one plugin is worth nothing at the other even if someone reused a secret. The caller and the plugin share a
secret that never crosses the wire. Every request carries
    X-Sbx-Time   Unix time in seconds
    X-Sbx-Nonce  16 to 64 characters [A-Za-z0-9_-], never reused
    X-Sbx-Mac    hex HMAC-SHA256 over request_message(...)
and every signed response carries X-Sbx-Mac over response_message(...), bound to the request's nonce, so a man in the
middle can neither forge an answer nor replay an old one. The plugin refuses a request older or newer than MAX_SKEW
seconds, or with a nonce it has seen. Only the path (below the maubot instance) and the body are signed, never a query
string, so every call that needs a parameter carries it in a JSON body.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field

MAX_SKEW = 60
SECRET_MIN = 32
NONCE = re.compile(r"[A-Za-z0-9_-]{16,64}")
ROOM = re.compile(r"![^\s]{1,200}")
EVENT = re.compile(r"\$[^\s]{1,200}")
# One Matrix event must stay under 65536 bytes after encryption; the text goes in twice at most (body and
# m.new_content), so 30 KB of text is the limit. The caller splits longer texts.
TEXT_MAX = 30 * 1024
NAME_MAX = 80
# The largest picture (a PNG, as it is) for the bot's avatar or a room's icon; the request carries it as base64.
AVATAR_MAX = 2 * 1024 * 1024
AVATAR_BODY_MAX = AVATAR_MAX * 4 // 3 + 4 * 1024
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
# What the owner may send in one message; longer is cut off at the room, not queued.
INBOUND_MAX = 16 * 1024
QUEUE_MAX = 500
# Images from the owner: what is accepted, and how many wait in memory for the caller to fetch them.
IMAGE_MAX = 10 * 1024 * 1024
IMAGE_MIMES = ("image/png", "image/jpeg", "image/webp", "image/gif")
MEDIA_COUNT = 5
MEDIA_BYTES = 50 * 1024 * 1024
MEDIA_ID = re.compile(r"[A-Za-z0-9_-]{16,64}")
WAIT_MAX = 30


class Refused(Exception):
    """A request the plugin will not act on; the message is safe to return to the caller."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def request_message(method: str, path: str, ts: str, nonce: str, body: bytes) -> bytes:
    return "\n".join(["sbx-chat-request", method.upper(), path, ts, nonce, _sha256(body)]).encode()


def response_message(nonce: str, status: int, body: bytes) -> bytes:
    return "\n".join(["sbx-chat-response", nonce, str(status), _sha256(body)]).encode()


def mac(secret: bytes, message: bytes) -> str:
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def sign_request(secret: bytes, method: str, path: str, body: bytes, now: float | None = None) -> dict[str, str]:
    """The headers a caller sends. Used by the tests; sbx-chat implements the same."""
    ts = str(int(time.time() if now is None else now))
    nonce = secrets.token_urlsafe(24)
    return {"X-Sbx-Time": ts, "X-Sbx-Nonce": nonce,
            "X-Sbx-Mac": mac(secret, request_message(method, path, ts, nonce, body))}


class Nonces:
    """Nonces seen in the last 2 * MAX_SKEW seconds; older ones are refused by the time check anyway."""

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}

    def use(self, nonce: str, now: float) -> bool:
        self.prune(now)
        if nonce in self._seen:
            return False
        self._seen[nonce] = now
        return True

    def prune(self, now: float) -> None:
        limit = now - 2 * MAX_SKEW
        for key in [k for k, t in self._seen.items() if t < limit]:
            del self._seen[key]


def check_request(secret: bytes | None, nonces: Nonces, method: str, path: str, headers, body: bytes,
                  now: float) -> str:
    """Return the request's nonce if it is signed correctly and fresh; raise Refused otherwise."""
    if secret is None:
        raise Refused(503, "no secret configured")
    ts, nonce, given = headers.get("X-Sbx-Time", ""), headers.get("X-Sbx-Nonce", ""), headers.get("X-Sbx-Mac", "")
    if not ts.isdigit() or not NONCE.fullmatch(nonce) or not given:
        raise Refused(401, "unsigned")
    if not hmac.compare_digest(mac(secret, request_message(method, path, ts, nonce, body)), given):
        raise Refused(401, "bad signature")
    if abs(now - int(ts)) > MAX_SKEW:
        raise Refused(401, "stale")
    if not nonces.use(nonce, now):
        raise Refused(401, "replayed")
    return nonce


def check_response(secret: bytes, nonce: str, status: int, body: bytes, given: str) -> bool:
    """What the caller checks before it trusts an answer."""
    return hmac.compare_digest(mac(secret, response_message(nonce, status, body)), given or "")


# --- request validation -------------------------------------------------------------------------------------------


def _object(data) -> dict:
    if not isinstance(data, dict):
        raise Refused(400, "body must be a JSON object")
    return data


def _text(data: dict, key: str = "text") -> str:
    text = data.get(key)
    if not isinstance(text, str) or not text.strip():
        raise Refused(400, f"bad {key}")
    if len(text.encode()) > TEXT_MAX:
        raise Refused(413, f"{key} too long")
    return text


def _room(data: dict) -> str:
    room = data.get("room")
    if not isinstance(room, str) or not ROOM.fullmatch(room):
        raise Refused(400, "bad room")
    return room


def _name(data: dict) -> str:
    name = data.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > NAME_MAX or "\n" in name:
        raise Refused(400, "bad name")
    return name


def parse_send(data) -> tuple[str, str]:
    data = _object(data)
    return _room(data), _text(data)


def parse_thread(data) -> str | None:
    """The event a /send message is to be a reply to in a thread (`thread`), or None for a plain message."""
    thread = _object(data).get("thread")
    if thread is None:
        return None
    if not isinstance(thread, str) or not EVENT.fullmatch(thread):
        raise Refused(400, "bad thread")
    return thread


def thread_relation(root: str) -> dict:
    """m.relates_to of a message in the thread of `root`; the same shape maubot-sbx-approval uses for its detail messages."""
    return {"rel_type": "m.thread", "event_id": root, "is_falling_back": True, "m.in_reply_to": {"event_id": root}}


def parse_edit(data) -> tuple[str, str, str]:
    data = _object(data)
    event = data.get("event")
    if not isinstance(event, str) or not EVENT.fullmatch(event):
        raise Refused(400, "bad event")
    return _room(data), event, _text(data)


def parse_room(data) -> str:
    return _name(_object(data))


def parse_nick(data) -> tuple[str, str]:
    """(room, the display name the bot takes in that room): one line, at most NAME_MAX characters."""
    data = _object(data)
    return _room(data), _name(data).strip()


def parse_avatar(data, clear_ok: bool) -> tuple[str, bytes | None]:
    """(room, the PNG bytes). `data` is the PNG as base64; an empty string means "remove the picture" (None) where clear_ok."""
    data = _object(data)
    room, raw = _room(data), data.get("data")
    if not isinstance(raw, str):
        raise Refused(400, "bad data")
    if raw == "":
        if clear_ok:
            return room, None
        raise Refused(400, "no image")
    if len(raw) > AVATAR_BODY_MAX:
        raise Refused(413, "image too large")
    try:
        image = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise Refused(400, "image is not base64")
    if len(image) > AVATAR_MAX:
        raise Refused(413, "image too large")
    if not image.startswith(PNG_MAGIC):
        raise Refused(400, "image is not a PNG")
    return room, image


def parse_archive(data) -> tuple[str, str]:
    data = _object(data)
    return _room(data), _name(data)


def parse_media(data) -> str:
    key = _object(data).get("id")
    if not isinstance(key, str) or not MEDIA_ID.fullmatch(key):
        raise Refused(400, "bad id")
    return key


def parse_events(data) -> tuple[str | None, int, float]:
    """(epoch the caller knows or None, last sequence number it has processed, seconds to wait)."""
    data = _object(data)
    epoch, after, wait = data.get("epoch"), data.get("after", 0), data.get("wait", 0)
    if epoch is not None and not isinstance(epoch, str):
        raise Refused(400, "bad epoch")
    if not isinstance(after, int) or isinstance(after, bool) or after < 0:
        raise Refused(400, "bad after")
    if not isinstance(wait, (int, float)) or isinstance(wait, bool) or not 0 <= wait <= WAIT_MAX:
        raise Refused(400, "bad wait")
    return epoch, after, float(wait)


# --- the inbound queue --------------------------------------------------------------------------------------------


@dataclass
class Inbox:
    """Messages of the owner not yet confirmed by the caller, in memory. The caller confirms by asking for what comes
    after the last sequence number it processed, so a lost answer only repeats messages. A restart of maubot starts a
    new epoch; a caller that sees a different epoch starts again at 0, so it is never left waiting for sequence numbers
    that will not come. Messages not fetched before a restart are lost, which the caller's room will show as no reply."""

    epoch: str = field(default_factory=lambda: secrets.token_urlsafe(9))
    seq: int = 0
    items: deque = field(default_factory=lambda: deque(maxlen=QUEUE_MAX))

    def add(self, room: str, text: str, event: str, image: dict | None = None) -> int:
        """image: {"id", "mime", "size"} of an attachment held in a MediaStore; the text is then its caption."""
        self.seq += 1
        item = {"seq": self.seq, "room": room, "text": text, "event": event}
        if image:
            item["image"] = image
        self.items.append(item)
        return self.seq

    def since(self, epoch: str | None, after: int) -> list[dict]:
        if epoch != self.epoch:
            after = 0
        return [dict(i) for i in self.items if i["seq"] > after]

    def reply(self, epoch: str | None, after: int) -> dict:
        return {"epoch": self.epoch, "events": self.since(epoch, after)}


class MediaStore:
    """Decrypted images in memory until the caller fetches them: at most MEDIA_COUNT and MEDIA_BYTES, the oldest dropped
    first. An image is served once and then gone. A restart of maubot loses them; the caller says so in the room."""

    def __init__(self) -> None:
        self._items: OrderedDict[str, tuple[str, bytes]] = OrderedDict()
        self._bytes = 0

    def put(self, mime: str, data: bytes) -> str:
        key = secrets.token_urlsafe(16)
        self._items[key] = (mime, data)
        self._bytes += len(data)
        while len(self._items) > MEDIA_COUNT or (self._bytes > MEDIA_BYTES and len(self._items) > 1):
            _, (_, old) = self._items.popitem(last=False)
            self._bytes -= len(old)
        return key

    def take(self, key: str) -> tuple[str, bytes] | None:
        found = self._items.pop(key, None)
        if found:
            self._bytes -= len(found[1])
        return found

    def __len__(self) -> int:
        return len(self._items)


def caption_of(content: dict) -> str:
    """Matrix caption convention: with a filename that differs from body, body is the caption; otherwise `body` is only
    the file name and there is no caption."""
    body, name = content.get("body"), content.get("filename")
    if isinstance(body, str) and isinstance(name, str) and name and name != body:
        return body.strip()
    return ""


def edit_content(event: str, text: str) -> dict:
    return {"msgtype": "m.text", "body": "* " + text, "m.new_content": {"msgtype": "m.text", "body": text},
            "m.relates_to": {"rel_type": "m.replace", "event_id": event}}


def is_edit(content: dict) -> bool:
    relates = content.get("m.relates_to") or {}
    return isinstance(relates, dict) and relates.get("rel_type") == "m.replace"
