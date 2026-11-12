# maubot-sbx-chat

A [maubot](https://github.com/maubot/maubot) plugin that is the Matrix side of a chat front end for Claude Code sessions in
an agent sandbox. It does three things for one person, the owner: it passes the owner's messages from one control room and
from the end-to-end encrypted session rooms it made to a program that polls for them, it posts that program's answers
(and edits an earlier answer, for a status line), and it makes and archives session rooms on request.

It holds no session state and runs no model or agent. The program behind it is `sbx-chat` on VM 130 of the homelab
(`sbx/sbx-chat.py` in `dag/agent-sandbox`); why this shape and what was rejected is recorded in the homelab repository's
ADR 0027 ("Matrix chat front end for the sessions of the local boxes"). It reuses the pattern of
[maubot-sbx-approval](https://github.com/d4g/maubot-sbx-approval) (ADR 0024).

**Status:** version 0.2.0 (images added), tested off-line (logic, and the HTTP endpoints of the real plugin class against maubot 0.6.0 /
mautrix 0.21.1 with a fake Matrix client, routed as maubot routes them). Not yet run against a real homeserver.

## Design in brief

- **One owner.** The bot account runs with autojoin off. The owner's MXID and the control room's ID are instance config.
  Messages of anyone else are ignored.
- **Which rooms.** The control room, and rooms this account created itself (checked on the room's `m.room.create` event
  after a restart, so the plugin needs no list of rooms). A room the owner invites it to is ignored even if someone joins.
- **Encrypted only.** As in sbx-approval, a message counts only if the server's copy of it is `m.room.encrypted`
  (maubot hands plugins an event without the decryption marker, so the plugin fetches the stored event and decrypts it
  again). Session rooms are created with `m.room.encryption` as initial state.
- **A new key when the owner joins.** The room is created with the owner only invited, and mautrix shares the first Megolm
  session with the joined members, which is the bot alone, and keeps it when the invitation becomes a join. So the plugin
  drops the room's outbound session when the owner joins (`on_member`), and the next message gets a session that includes
  the owner. What the bot sent before the join stays unreadable for the owner.
- **The caller always initiates.** The program on VM 130 polls `POST /events` and posts to the other endpoints; no port
  opens there and no Matrix key is stored there.
- **Signed with HMAC**, requests and responses, over a shared secret with timestamp and nonce (the scheme of
  sbx-approval, with the label lines `sbx-chat-request` and `sbx-chat-response`, so a signature for one plugin is
  worthless at the other). The secret never crosses the wire.
- **Images.** An `m.image` of the owner in a session room (not the control room) is accepted when it is an encrypted
  attachment (`content.file`; a plain `url` is refused, since the image would sit unencrypted on the homeserver), PNG, JPEG,
  WebP or GIF, and at most 10 MiB (checked on `info.size` before the download and on the real byte count after). The plugin
  downloads it, decrypts it itself (`mautrix.crypto.attachments.decrypt_attachment`), keeps the bytes in memory (at most 5
  images and 50 MB, the oldest dropped) and queues an event with `image: {id, mime, size}`; the caller fetches the bytes once
  with `POST /media`. The caption follows the Matrix convention: if `filename` is set and differs from `body`, `body` is the
  caption. Every other message type (`m.file`, `m.audio`, `m.video`, `m.emote`) and every refused image gets a short
  `m.notice`; edits and `m.notice` are ignored. The plugin never writes to the caller's host.
- **No session state in the plugin.** The inbound queue and the image store are in memory (500 messages, 5 images).
- **Nothing site-specific in this repository.** Secret, room and owner live in maubot's instance config.

## API

All under the instance's web path, `<maubot>/_matrix/maubot/plugin/<instance id>/`, all `POST` with a JSON body, because
only path and body are signed and a query string would not be. Every request is signed (below); an unsigned, wrongly
signed, stale or replayed request gets `401` without a signature, and `503` while no secret is set.

| Request | Body | Answer (signed) |
|---|---|---|
| `POST /events` | `{"epoch"?, "after"?, "wait"?}` — the epoch the caller last saw, the last sequence number it processed, seconds to wait for a message (0 to 30) | `200 {"epoch", "events": [{"seq", "room", "text", "event", "image"?}, …]}` — everything after `after`; `text` is the caption of an image, possibly empty; waits until there is something or `wait` ran out |
| `POST /media` | `{"id"}` — the `image.id` of an event | `200 {"mime", "data"}` (base64), **once**: the image is removed when served; signed `404` if unknown (served already, dropped, or maubot restarted) |
| `POST /send` | `{"room", "text", "thread"?}` — text ≤ 30 KiB UTF-8, plain (no markup is built from it); `thread`: the event ID of a message this account sent, then the text is a reply in that message's thread (`m.thread`), as maubot-sbx-approval does for its detail | `201 {"event", "thread"?}` (`thread` repeated, so a caller can tell that this version knew the field); `403` not a room of this plugin; `413`; `502` |
| `POST /edit` | `{"room", "event", "text"}` — replaces an earlier message of this account (`m.replace`) | `200 {"event"}` |
| `POST /room` | `{"name", "space"?}` — name ≤ 80 characters; `space`: `dev`, `orchestrator` or `rp` (else `400`) | `201 {"room", "space"?}` — private, encrypted from creation, the owner invited. With `space`, the room claims that sub-space (`m.space.parent`) and is listed in it (`m.space.child`); `space` is repeated, `null` if the listing failed (the room is made anyway), so a caller can tell that this version knew the field |
| `POST /spaces` | `{}` | `200 {"spaces": {"parent", "dev", "orchestrator", "rp"}}` (room IDs) — missing spaces made, the control room, the `approval_room` and the sub-spaces linked into the parent; `502` |
| `POST /place` | `{"room", "space"}` — the control room or a room this plugin made | `200 {"space"}` — listed in that sub-space unless it is already (no event is sent then); `400` bad space, `403` foreign room, `502` |
| `POST /nick` | `{"room", "name"}` — one line, ≤ 80 characters | `200 {"nick"}` — the bot's own display name in that room (its own member event, avatar kept); `403` for the control room or a foreign room |
| `POST /avatar` | `{"room", "data"}` — a PNG as base64 (≤ 2 MiB), or `""` to remove | `200 {"avatar"}` — uploaded to the homeserver's media repository (**not encrypted**; only the homeserver's admin can delete it) and set as the avatar of the bot's own member event; the name stays. `400` not a PNG; `403` control room or foreign room; `413` |
| `POST /roomicon` | `{"room", "data"}` — a PNG as base64 (≤ 2 MiB) | `200 {"icon": true}` — the room's icon (`m.room.avatar`), uploaded like `/avatar` |
| `POST /archive` | `{"room", "name"}` | `200 {"archived": true}` — renames the room, takes it out of its space, then leaves it; never the control room |

**Events and restarts.** The caller confirms by sending the last sequence number it processed, so a lost answer only
repeats messages. Every start of the plugin makes a new random `epoch`; a caller that sends another epoch gets all queued
messages and must start counting again, so a maubot restart cannot leave it waiting for sequence numbers that never come.
Messages and images not fetched before a restart are lost; the caller says so in the room. Messages over 16 KiB are not queued; the owner gets a notice.

**Signature.** Headers `X-Sbx-Time` (Unix seconds), `X-Sbx-Nonce` (16 to 64 of `[A-Za-z0-9_-]`, fresh per request) and
`X-Sbx-Mac`, the hex HMAC-SHA256 with the shared secret over these lines joined by `\n`:

```text
sbx-chat-request
<METHOD>
<path below the instance, e.g. /send — maubot strips /_matrix/maubot/plugin/<instance> before the plugin sees it>
<X-Sbx-Time>
<X-Sbx-Nonce>
<hex SHA-256 of the body>
```

Requests more than 60 s off the plugin's clock, or with a nonce seen in the last 120 s, are refused. A signed answer
carries `X-Sbx-Mac` over `sbx-chat-response`, the request's nonce, the status code and the body's SHA-256, joined the same
way; a caller must check it before it trusts the answer. `core.sign_request` and `core.check_response` are the reference.

## Spaces

The owner's room list stays ordered by Matrix spaces, which the plugin makes itself on the first `/spaces` (the caller sends it when it
starts), or the first time a room is placed (`/room` with `space`, or `/place`): a parent space "Agent sandbox" (the control room, the `approval_room`, and three sub-spaces) and
the sub-spaces "Dev", "Orchestrator" and "Rollenspiel". They are private (invite only, not in the directory), **not
encrypted** (a space carries only names and links, which the owner's own homeserver sees anyway), and the owner is invited
with power level 100 next to the bot so the owner can move rooms by hand. Their IDs are saved with the instance config
(`spaces.*`, `self.config.save()`) right after each is made, so a restart never makes a second copy. A space the owner
deletes is not noticed; empty its key to have a new one made. Linking is best effort and never fails a request.

## Configuration

Per instance in the maubot UI ([`base-config.yaml`](base-config.yaml)): `owner`, `room_id` (control room), `secret` (≥ 32
characters). `approval_room` (optional: the room of
maubot-sbx-approval, put into the parent space). `spaces.parent`, `spaces.dev`, `spaces.orchestrator`, `spaces.rp` are filled
by the plugin itself (see below); leave them empty. The instance id is part of the URL the caller uses; the homelab uses `chat`.

## Tests

```bash
uv run --no-project --managed-python --python 3.13 --with maubot==0.6.0 --with pytest --with pytest-aiohttp \
  --with unpaddedbase64 --with pycryptodome pytest tests
```

`tests/test_core.py` needs only pytest; `tests/test_web.py` is skipped without maubot. The image tests need `unpaddedbase64` and
`pycryptodome` (what `mautrix.crypto.attachments` imports); `tests/conftest.py` stands in for the package `mautrix.crypto` when
python-olm is missing, since only the attachment submodule is used. On the real maubot both packages come with its encryption
support, since the bot's account is end-to-end encrypted.

## Deployment

Built on NixOS with `buildMaubotPlugin` and `fetchFromGitHub`, **pinned to a commit hash**; a change here runs only after the
pin is changed on the host. `pname` and `version` must equal `id` and `version` in [`maubot.yaml`](maubot.yaml):

```nix
sbxChat = config.services.maubot.package.plugins.buildMaubotPlugin {
  pname = "rocks.dag.sbx-chat";
  version = "0.2.0";
  src = pkgs.fetchFromGitHub {
    owner = "d4g";
    repo = "maubot-sbx-chat";
    rev = "<commit>";
    hash = "<hash from the first failing build>";
  };
};
```

## License

[Unlicense](LICENSE) — public domain.
