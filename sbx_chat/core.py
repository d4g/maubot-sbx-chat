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
import html
import re
import secrets
import time
import unicodedata
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
# The sub-spaces a session room can be put in (the keys of the config's `spaces`, besides `parent`) and the names they are
# created with. The owner sees the names in Element, so these are what the owner reads; the keys are what the caller sends.
SUBSPACES = {"dev": "Dev", "orchestrator": "Orchestrator", "rp": "RP"}      # rp was "Rollenspiel" until 0.9.0
PARENT_SPACE = "Agent sandbox"
# The sub-space of the fixed rooms (the control room and the approval room of sbx-approval), config key `spaces.admin`. Not in
# SUBSPACES: /room and /place never put a session room there. Wish of the user 2026-11-14.
ADMIN_SPACE = "Admin"


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


def _event(data: dict) -> str:
    event = data.get("event")
    if not isinstance(event, str) or not EVENT.fullmatch(event):
        raise Refused(400, "bad event")
    return event


def parse_edit(data) -> tuple[str, str, str]:
    data = _object(data)
    return _room(data), _event(data), _text(data)


def parse_redact(data) -> tuple[str, str]:
    """(room, the event to redact): an event ID is a string that starts with `$` (EVENT: at most 201 characters, no whitespace)."""
    data = _object(data)
    return _room(data), _event(data)


REACT_KEY_MAX = 32


def parse_react(data) -> tuple[str, str, str]:
    """(room, the event to react to, the reaction key). The key is what the reaction shows, an emoji as a rule: 1 to
    REACT_KEY_MAX characters (not bytes), none of them a control character (Unicode category Cc, or a lone surrogate, Cs; format
    characters such as the zero-width joiner and variation selectors stay allowed, because emoji are made of them)."""
    data = _object(data)
    key = data.get("key")
    if not isinstance(key, str) or not 1 <= len(key) <= REACT_KEY_MAX:
        raise Refused(400, "bad key")
    if any(unicodedata.category(c) in ("Cc", "Cs") for c in key):
        raise Refused(400, "bad key")
    return _room(data), _event(data), key


def parse_markdown(data) -> bool:
    """`markdown` of /send and /edit: absent means False. Anything but a JSON boolean is refused, so that a typo such as
    "yes" or 1 is an error at the caller instead of a message that silently goes out unformatted."""
    value = _object(data).get("markdown", False)
    if not isinstance(value, bool):
        raise Refused(400, "bad markdown")
    return value


def parse_notice(data) -> bool:
    """`notice` of /send: absent means False (an m.text message); true sends an m.notice, which clients show dimmed and which
    never notifies (push rule .m.rule.suppress_notices). Anything but a JSON boolean is refused, as for `markdown`."""
    value = _object(data).get("notice", False)
    if not isinstance(value, bool):
        raise Refused(400, "bad notice")
    return value


TYPING_MAX_MS = 120_000


def parse_typing(data) -> tuple[str, int]:
    """(room, timeout in milliseconds) of /typing; 0 means "stopped typing". `typing` must be a JSON boolean; with true,
    `timeout` is a whole number of milliseconds from 1 to TYPING_MAX_MS (the spec recommends that the client refreshes the
    state every 20 to 30 seconds, so a long timeout is never needed); with false it is ignored."""
    data = _object(data)
    typing = data.get("typing")
    if not isinstance(typing, bool):
        raise Refused(400, "bad typing")
    if not typing:
        return _room(data), 0
    timeout = data.get("timeout")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= TYPING_MAX_MS:
        raise Refused(400, "bad timeout")
    return _room(data), timeout


def parse_room(data) -> str:
    return _name(_object(data))


def parse_space(data, required: bool = False) -> str | None:
    """The sub-space (`space`, one of SUBSPACES) a room is to be put in; None if the field is absent and not `required`."""
    space = _object(data).get("space")
    if space is None and not required:
        return None
    if not isinstance(space, str) or space not in SUBSPACES:
        raise Refused(400, "bad space")
    return space


def parse_place(data) -> tuple[str, str]:
    data = _object(data)
    return _room(data), parse_space(data, required=True)


def space_link(server: str, canonical: bool = False) -> dict:
    """Content of an m.space.child (sent into the space, state_key = the room) or of an m.space.parent (sent into the room,
    state_key = the space). Both need `via`, the servers to join through: without it a client ignores the link, and a child
    event with empty content or no `via` means "removed" (Matrix spec, "Spaces",
    https://spec.matrix.org/v1.11/client-server-api/#spaces). `canonical` marks the primary parent and exists on
    m.space.parent only."""
    return {"via": [server], **({"canonical": True} if canonical else {})}


def has_link(content) -> bool:
    """True if an m.space.child as read from the server is a live link: a non-empty `via` list."""
    via = content.get("via") if isinstance(content, dict) else None
    return isinstance(via, list) and bool(via)


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

    def add(self, room: str, text: str, event: str, image: dict | None = None, thread: str | None = None) -> int:
        """image: {"id", "mime", "size"} of an attachment held in a MediaStore; the text is then its caption.
        thread: the event ID of the root of the Matrix thread the message was sent in (see thread_of), None outside a thread."""
        self.seq += 1
        item = {"seq": self.seq, "room": room, "text": text, "event": event}
        if image:
            item["image"] = image
        if thread:
            item["thread"] = thread
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


# --- formatted text (a Markdown subset to HTML) ------------------------------------------------------------------

HTML_FORMAT = "org.matrix.custom.html"
# The word after an opening fence that becomes the class `language-<word>` of the code element (the Matrix spec lets a
# client keep only classes that start with `language-`, for syntax highlighting). Anything else is not taken for a language.
LANG = r"[A-Za-z0-9_+-]{1,20}"
FENCE = re.compile(r"```(?:(" + LANG + r")[ \t]*\n|[ \t]*\n)?(.*?)```", re.DOTALL)
INLINE_CODE = re.compile(r"`([^`\n]+)`")
STRONG = re.compile(r"\*\*(?=[^\s*])(.+?)(?<=[^\s*])\*\*")
# A single * or _ opens only before a non-space and closes only after a non-space, and neither may touch a word character on
# its outer side: "2 * 3 * 4" and "snake_case_name" stay as they are.
EM_STAR = re.compile(r"(?<![*\w])\*(?=[^\s*])([^*\n]+?)(?<=[^\s*])\*(?![*\w])")
EM_UNDER = re.compile(r"(?<!\w)_(?=[^\s_])([^_\n]+?)(?<=[^\s_])_(?!\w)")


def _em(text: str) -> str:
    return EM_UNDER.sub(r"<em>\1</em>", EM_STAR.sub(r"<em>\1</em>", text))


def _emphasis(text: str) -> str:
    """**strong** and *em* / _em_ in text that is already escaped and holds no code. Strong is cut out first and its inside
    and the rest are handled on their own, so spans can never overlap into misnested tags: `**a *b** c*` leaves the single
    star literal. An unclosed marker has no match and stays as text. A loop, not recursion: a 30 KiB text can hold thousands
    of strong spans, more than Python's recursion limit."""
    out, last = [], 0
    for found in STRONG.finditer(text):
        out.append(_em(text[last:found.start()]) + "<strong>" + _em(found.group(1)) + "</strong>")
        last = found.end()
    out.append(_em(text[last:]))
    return "".join(out)


def _prose(text: str) -> str:
    """Escaped text outside a fence: inline code first (nothing inside it is converted), emphasis in the pieces between, and
    a line break for every newline."""
    out, last = [], 0
    for found in INLINE_CODE.finditer(text):
        out.append(_emphasis(text[last:found.start()]))
        out.append("<code>" + found.group(1) + "</code>")
        last = found.end()
    out.append(_emphasis(text[last:]))
    return "".join(out).replace("\n", "<br>")


def markdown_html(text: str) -> str:
    """The `formatted_body` (format `org.matrix.custom.html`) for a text written in a small subset of Markdown.

    Order matters and is the whole safety argument: the WHOLE text is HTML-escaped first (html.escape with quote=True, so
    `<`, `>`, `&`, `"` and `'` become entities), and only then are markers turned into tags. Every tag in the result is
    therefore one this function wrote; nothing the author typed (a <script>, an <img onerror=...>, an attribute) can reach the
    output as markup. The markers themselves (backtick, star, underscore) are not touched by escaping, so they still work.

    Only closed spans are converted; an unclosed marker stays literal text. Rules:
      a fenced block (three backticks, an optional language word, a line break, the code, three backticks) becomes
        <pre><code class="language-x">...</code></pre>; the word is kept only if it matches LANG, else the block has no
        class; the inside is escaped text and nothing in it is converted
      `x`        <code>x</code>, nothing inside converted
      **x**      <strong>x</strong>
      *x*, _x_   <em>x</em>; an underscore inside a word (snake_case) is never emphasis
      newline    <br>, outside fenced blocks
    No links, no other tags, no attributes except the class of a fenced block. `body` of the message stays the raw text."""
    text = html.escape(text.replace("\r\n", "\n"), quote=True)
    out, last = [], 0
    for found in FENCE.finditer(text):
        out.append(_prose(text[last:found.start()]))
        lang, code = found.group(1), found.group(2)
        if code.endswith("\n"):
            code = code[:-1]                # the line break before the closing fence is not part of the code
        out.append("<pre><code" + (f' class="language-{lang}"' if lang else "") + ">" + code + "</code></pre>")
        last = found.end()
    out.append(_prose(text[last:]))
    return "".join(out)


def message_content(text: str, markdown: bool = False, notice: bool = False) -> dict:
    """Content of an m.text message (an m.notice with `notice`). With `markdown` it also carries format and formatted_body
    (markdown_html); `body` is the raw text either way, which is what a client without HTML shows."""
    content = {"msgtype": "m.notice" if notice else "m.text", "body": text}
    if markdown:
        content.update({"format": HTML_FORMAT, "formatted_body": markdown_html(text)})
    return content


def edit_content(event: str, text: str, markdown: bool = False) -> dict:
    """An m.replace edit. The outer content is the fallback for clients that do not know edits ("* " in front, as the spec
    example shows) and carries the formatting too; m.new_content is what the message becomes."""
    outer = message_content("* " + text)
    if markdown:
        outer.update({"format": HTML_FORMAT, "formatted_body": "* " + markdown_html(text)})
    return {**outer, "m.new_content": message_content(text, markdown),
            "m.relates_to": {"rel_type": "m.replace", "event_id": event}}


def thread_of(content: dict) -> str | None:
    """The root of the Matrix thread an incoming message is in: m.relates_to with rel_type m.thread and an event_id. Only that
    counts: a thread reply carries a fallback m.in_reply_to as well, but a plain reply (m.in_reply_to alone) is not in a thread."""
    relates = content.get("m.relates_to")
    if isinstance(relates, dict) and relates.get("rel_type") == "m.thread":
        root = relates.get("event_id")
        if isinstance(root, str) and EVENT.fullmatch(root):
            return root
    return None


def is_edit(content: dict) -> bool:
    relates = content.get("m.relates_to") or {}
    return isinstance(relates, dict) and relates.get("rel_type") == "m.replace"
