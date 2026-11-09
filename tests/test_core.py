import hashlib
import hmac
import pathlib
import sys

import pytest

# core.py on its own: the package's __init__ needs maubot, which these tests do not.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "sbx_chat"))
import core  # noqa: E402

SECRET = b"s" * 40
T0 = 1_800_000_000.0


def check(headers, method="POST", path="/send", body=b"{}", nonces=None, now=T0, secret=SECRET):
    return core.check_request(secret, nonces or core.Nonces(), method, path, headers, body, now)


def signed(method="POST", path="/send", body=b"{}", now=T0, secret=SECRET):
    return core.sign_request(secret, method, path, body, now)


def test_good_request_and_response():
    headers = signed()
    nonce = check(headers)
    assert nonce == headers["X-Sbx-Nonce"]
    mac = core.mac(SECRET, core.response_message(nonce, 201, b"{}"))
    assert core.check_response(SECRET, nonce, 201, b"{}", mac)
    assert not core.check_response(SECRET, nonce, 200, b"{}", mac)
    assert not core.check_response(SECRET, nonce, 201, b"{}", "")


@pytest.mark.parametrize("sign,verify,message", [
    (dict(secret=b"x" * 40), {}, "bad signature"),
    ({}, dict(path="/edit"), "bad signature"),
    ({}, dict(method="GET"), "bad signature"),
    ({}, dict(body=b'{"a":1}'), "bad signature"),
    ({}, dict(now=T0 + 61), "stale"),
    ({}, dict(now=T0 - 61), "stale"),
])
def test_refused(sign, verify, message):
    with pytest.raises(core.Refused) as error:
        check(signed(**sign), **verify)
    assert error.value.message == message and error.value.status == 401


def test_replay_unsigned_and_no_secret():
    headers, nonces = signed(), core.Nonces()
    check(headers, nonces=nonces)
    with pytest.raises(core.Refused, match="replayed"):
        check(headers, nonces=nonces)
    with pytest.raises(core.Refused, match="unsigned"):
        check({})
    with pytest.raises(core.Refused) as error:
        check(signed(), secret=None)
    assert error.value.status == 503


def test_approval_plugin_signatures_are_worthless_here():
    """Same scheme, different label line: a signature made for sbx-approval does not pass."""
    body = b"{}"
    message = "\n".join(["sbx-approval-request", "POST", "/send", str(int(T0)), "n" * 20,
                         hashlib.sha256(body).hexdigest()]).encode()
    headers = {"X-Sbx-Time": str(int(T0)), "X-Sbx-Nonce": "n" * 20,
               "X-Sbx-Mac": hmac.new(SECRET, message, hashlib.sha256).hexdigest()}
    with pytest.raises(core.Refused, match="bad signature"):
        check(headers)


def test_validation():
    assert core.parse_send({"room": "!a:b", "text": "hi"}) == ("!a:b", "hi")
    for bad in ([], {"room": "a:b", "text": "x"}, {"room": "!a:b", "text": " "}, {"room": "!a:b"},
                {"room": "!a b", "text": "x"}):
        with pytest.raises(core.Refused):
            core.parse_send(bad)
    with pytest.raises(core.Refused) as error:
        core.parse_send({"room": "!a:b", "text": "x" * (core.TEXT_MAX + 1)})
    assert error.value.status == 413
    assert core.parse_edit({"room": "!a:b", "event": "$e", "text": "t"}) == ("!a:b", "$e", "t")
    with pytest.raises(core.Refused):
        core.parse_edit({"room": "!a:b", "event": "e", "text": "t"})
    assert core.parse_room({"name": "local/x"}) == "local/x"
    for bad in ({"name": ""}, {"name": "a\nb"}, {"name": "x" * 81}, {}):
        with pytest.raises(core.Refused):
            core.parse_room(bad)
    assert core.parse_archive({"room": "!a:b", "name": "n"}) == ("!a:b", "n")
    assert core.parse_events({}) == (None, 0, 0.0)
    assert core.parse_events({"epoch": "e", "after": 3, "wait": 25}) == ("e", 3, 25.0)
    for bad in ({"after": -1}, {"after": True}, {"wait": 31}, {"epoch": 1}, {"after": "1"}):
        with pytest.raises(core.Refused):
            core.parse_events(bad)


def test_inbox_after_and_epoch():
    inbox = core.Inbox()
    inbox.add("!a:b", "one", "$1")
    inbox.add("!a:b", "two", "$2")
    first = inbox.reply(None, 0)
    assert [e["text"] for e in first["events"]] == ["one", "two"]
    epoch = first["epoch"]
    assert [e["text"] for e in inbox.reply(epoch, 1)["events"]] == ["two"]
    assert inbox.reply(epoch, 2)["events"] == []
    # A caller that knows the old epoch of a restarted plugin (sequence numbers start again) gets everything.
    restarted = core.Inbox()
    restarted.add("!a:b", "after restart", "$3")
    stale = restarted.reply(epoch, 2)
    assert stale["epoch"] != epoch and [e["text"] for e in stale["events"]] == ["after restart"]


def test_inbox_is_bounded():
    inbox = core.Inbox()
    for n in range(core.QUEUE_MAX + 10):
        inbox.add("!a:b", str(n), f"${n}")
    assert len(inbox.items) == core.QUEUE_MAX and inbox.items[0]["text"] == "10"


def test_edit_content():
    content = core.edit_content("$e", "new")
    assert content["m.new_content"]["body"] == "new" and content["m.relates_to"]["event_id"] == "$e"
    assert core.is_edit(content) and not core.is_edit({"body": "x"})
