import base64
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


def test_media_store_serves_once_and_drops_the_oldest():
    store = core.MediaStore()
    keys = [store.put("image/png", b"x") for _ in range(core.MEDIA_COUNT + 1)]
    assert len(store) == core.MEDIA_COUNT and store.take(keys[0]) is None
    assert store.take(keys[1]) == ("image/png", b"x") and store.take(keys[1]) is None


def test_media_store_byte_limit():
    store = core.MediaStore()
    first = store.put("image/png", b"x" * (30 * 1024 * 1024))
    second = store.put("image/png", b"y" * (30 * 1024 * 1024))
    assert store.take(first) is None and store.take(second) is not None


def test_caption_convention():
    assert core.caption_of({"body": "a cat", "filename": "cat.png"}) == "a cat"
    assert core.caption_of({"body": "cat.png", "filename": "cat.png"}) == ""
    assert core.caption_of({"body": "cat.png"}) == ""


def test_inbox_item_carries_the_image():
    inbox = core.Inbox()
    inbox.add("!r", "", "$e", {"id": "i", "mime": "image/png", "size": 3})
    inbox.add("!r", "t", "$f")
    first, second = inbox.since(None, 0)
    assert first["image"]["id"] == "i" and "image" not in second


def test_parse_space_and_place():
    assert core.parse_space({}) is None and core.parse_space({"space": None}) is None
    assert [core.parse_space({"space": k}) for k in ("dev", "orchestrator", "rp")] == ["dev", "orchestrator", "rp"]
    for bad in ("parent", "", "Dev", 1, ["dev"]):
        with pytest.raises(core.Refused) as error:
            core.parse_space({"space": bad})
        assert error.value.status == 400
    with pytest.raises(core.Refused):
        core.parse_space({}, required=True)
    assert core.parse_place({"room": "!r:x", "space": "rp"}) == ("!r:x", "rp")
    with pytest.raises(core.Refused):
        core.parse_place({"room": "r", "space": "rp"})


def test_space_links():
    assert core.space_link("example.org") == {"via": ["example.org"]}
    assert core.space_link("example.org", canonical=True) == {"via": ["example.org"], "canonical": True}
    assert core.has_link({"via": ["example.org"]}) and not core.has_link({}) and not core.has_link({"via": []})
    assert not core.has_link({"via": "example.org"}) and not core.has_link(None)


# --- formatted text -----------------------------------------------------------------------------------------------

import re  # noqa: E402

OUR_TAGS = re.compile(r'</?(?:pre|code|strong|em|br)(?: class="language-[A-Za-z0-9_+-]{1,20}")?>')


def only_ours(html_text):
    """What is left of formatted_body after the tags the converter writes are removed: it must hold no `<` at all."""
    return OUR_TAGS.sub("", html_text)


@pytest.mark.parametrize("text,expected", [
    ("plain", "plain"),
    ("**bold**", "<strong>bold</strong>"),
    ("*it* and _it_", "<em>it</em> and <em>it</em>"),
    ("`x`", "<code>x</code>"),
    ("a\nb", "a<br>b"),
    ("**a *b* c**", "<strong>a <em>b</em> c</strong>"),
    ("```\ncode\n```", "<pre><code>code</code></pre>"),
    ("```python\nx = 1\n```", '<pre><code class="language-python">x = 1</code></pre>'),
    ("```c++\nint x;\n```", '<pre><code class="language-c++">int x;</code></pre>'),
    ("before\n```\na\n\nb\n```\nafter", "before<br><pre><code>a\n\nb</code></pre><br>after"),
    ("```inline```", "<pre><code>inline</code></pre>"),
    # not converted: unclosed, unbalanced, inside words, spaced stars
    ("**unclosed", "**unclosed"),
    ("*unclosed", "*unclosed"),
    ("`unclosed", "`unclosed"),
    ("```\nunclosed fence", "```<br>unclosed fence"),
    ("a_b_c", "a_b_c"),
    ("snake_case_name and my_var", "snake_case_name and my_var"),
    ("2 * 3 * 4", "2 * 3 * 4"),
    ("** spaced **", "** spaced **"),
    ("____", "____"),
    # code is not converted inside
    ("`**x** _y_`", "<code>**x** _y_</code>"),
    ("```\n**x** `y` _z_\n```", "<pre><code>**x** `y` _z_</code></pre>"),
    ("```\na `b` c\n```", "<pre><code>a `b` c</code></pre>"),
    # a language word that is not one is not a class
    ("```py thon\nx\n```", "<pre><code>py thon\nx</code></pre>"),
    ("```" + "a" * 21 + "\nx\n```", "<pre><code>" + "a" * 21 + "\nx</code></pre>"),
    # escaping
    ("a & b \"q\" 'r'", "a &amp; b &quot;q&quot; &#x27;r&#x27;"),
    ("1 < 2 > 0", "1 &lt; 2 &gt; 0"),
    ("a\r\nb", "a<br>b"),
])
def test_markdown_html(text, expected):
    assert core.markdown_html(text) == expected


def test_markdown_thousands_of_strong_spans_do_not_hit_the_recursion_limit():
    text = "**a** " * 5000                    # 30 KiB, the largest text /send takes
    assert core.markdown_html(text).count("<strong>a</strong>") == 5000


def test_markdown_overlapping_markers_never_misnest():
    assert core.markdown_html("**a *b** c*") == "<strong>a *b</strong> c*"
    assert core.markdown_html("*a **b* c**") == "*a <strong>b* c</strong>"
    assert core.markdown_html("**a `b** c` d") == "**a <code>b** c</code> d"
    # whatever the input, every opening tag is closed by its own closing tag, in order
    for text in ("**a _b** c_", "_a *b_ c*", "***x***", "*_x_*", "**`x`**", "`a` `b` **c** _d_ ```\ne\n```"):
        stack = []
        for closing, tag in re.findall(r"<(/?)(strong|em|code|pre)[ >]", core.markdown_html(text) + " "):
            if closing:
                assert stack and stack.pop() == tag, text
            else:
                stack.append(tag)
        assert stack == [], text


HOSTILE = [
    "<script>alert(1)</script>",
    "**<b>x</b>**",
    "*<b>x</b>* and _<i>x</i>_",
    "<img src=x onerror=alert(1)>",
    "**<img src=x onerror=alert(1)>**",
    "`<img src=x onerror=alert(1)>`",
    "```\n<img src=x onerror=alert(1)>\n```",
    "```<script>x</script>\n<script>y</script>\n```",
    "```js\n<script>alert(1)</script>\n```",
    "```\"><script>alert(1)</script>\n```",
    "```x\"onmouseover=\"alert(1)\n```",
    "**a <b>b** c</b> _d <i>e_ </i>",
    "*a **<u>b* c</u>**",
    "``` `<b>` ```",
    "`a` **<a href=\"javascript:alert(1)\">x</a>** `b`",
    "&lt;script&gt; &amp;lt; &#60;script&#62;",
    "a & b \"q\" 'r' <&\"'>",
    "<<script>script>alert(1)<</script>/script>",
    "\x00<script>\x00",
]


@pytest.mark.parametrize("text", HOSTILE)
def test_markdown_hostile_input_never_reaches_the_html_as_markup(text):
    out = core.markdown_html(text)
    rest = only_ours(out)
    assert "<" not in rest and ">" not in rest, out
    assert not re.search(r"<(?!/?(?:pre|code|strong|em|br)[ >])", out), out
    # the only attribute a tag of ours may have is the language class
    assert not re.search(r"<[^>]*=(?!\"language-)", out), out


def test_markdown_an_ampersand_in_the_input_is_escaped_and_entities_are_not_decoded():
    assert core.markdown_html("&lt;b&gt;") == "&amp;lt;b&amp;gt;"


def test_message_content_body_stays_raw():
    assert core.message_content("**x** <b>") == {"msgtype": "m.text", "body": "**x** <b>"}
    assert core.message_content("**x** <b>", True) == {
        "msgtype": "m.text", "body": "**x** <b>", "format": "org.matrix.custom.html",
        "formatted_body": "<strong>x</strong> &lt;b&gt;"}


def test_edit_content_markdown():
    content = core.edit_content("$e", "**new**", True)
    assert content["body"] == "* **new**" and content["formatted_body"] == "* <strong>new</strong>"
    assert content["format"] == "org.matrix.custom.html"
    assert content["m.new_content"] == {"msgtype": "m.text", "body": "**new**", "format": "org.matrix.custom.html",
                                        "formatted_body": "<strong>new</strong>"}
    assert content["m.relates_to"] == {"rel_type": "m.replace", "event_id": "$e"}
    plain = core.edit_content("$e", "new")
    assert "formatted_body" not in plain and "formatted_body" not in plain["m.new_content"]


def test_parse_markdown():
    assert core.parse_markdown({}) is False and core.parse_markdown({"markdown": False}) is False
    assert core.parse_markdown({"markdown": True}) is True
    for bad in ("true", 1, 0, None, [], {}):
        with pytest.raises(core.Refused) as error:
            core.parse_markdown({"markdown": bad})
        assert error.value.status == 400


def test_parse_redact():
    assert core.parse_redact({"room": "!a:b", "event": "$e:x"}) == ("!a:b", "$e:x")
    for bad in ({"room": "!a:b"}, {"room": "!a:b", "event": "e"}, {"room": "!a:b", "event": ""},
                {"room": "!a:b", "event": "$a b"}, {"room": "!a:b", "event": 5},
                {"room": "!a:b", "event": "$" + "x" * 201}, {"event": "$e"}, {"room": "a", "event": "$e"}, []):
        with pytest.raises(core.Refused) as error:
            core.parse_redact(bad)
        assert error.value.status == 400, bad
    assert core.parse_redact({"room": "!a:b", "event": "$" + "x" * 200})[1] == "$" + "x" * 200


def test_parse_react():
    assert core.parse_react({"room": "!a:b", "event": "$e:x", "key": "🔁"}) == ("!a:b", "$e:x", "🔁")
    # an emoji made of several code points (variation selector, zero-width joiner) is one key
    assert core.parse_react({"room": "!a:b", "event": "$e", "key": "❤️"})[2] == "❤️"
    assert core.parse_react({"room": "!a:b", "event": "$e", "key": "x" * 32})[2] == "x" * 32
    for bad in ({"room": "!a:b", "event": "$e"}, {"room": "!a:b", "event": "$e", "key": ""},
                {"room": "!a:b", "event": "$e", "key": "x" * 33}, {"room": "!a:b", "event": "$e", "key": 5},
                {"room": "!a:b", "event": "$e", "key": "a\nb"}, {"room": "!a:b", "event": "$e", "key": "\x00"},
                {"room": "!a:b", "event": "$e", "key": "\x7f"}, {"room": "!a:b", "key": "x"},
                {"room": "!a:b", "event": "e", "key": "x"}, {"event": "$e", "key": "x"}, []):
        with pytest.raises(core.Refused) as error:
            core.parse_react(bad)
        assert error.value.status == 400, bad


def test_thread_of():
    thread = {"rel_type": "m.thread", "event_id": "$root", "is_falling_back": True, "m.in_reply_to": {"event_id": "$r"}}
    assert core.thread_of({"m.relates_to": thread}) == "$root"
    assert core.thread_of({"m.relates_to": {"rel_type": "m.thread", "event_id": "$root"}}) == "$root"
    # a plain reply, an edit, a thread without a root, a bad root, and no relation are not in a thread
    for content in ({}, {"m.relates_to": {"m.in_reply_to": {"event_id": "$r"}}},
                    {"m.relates_to": {"rel_type": "m.replace", "event_id": "$o"}},
                    {"m.relates_to": {"rel_type": "m.thread"}}, {"m.relates_to": {"rel_type": "m.thread", "event_id": 5}},
                    {"m.relates_to": {"rel_type": "m.thread", "event_id": "root"}}, {"m.relates_to": "x"},
                    {"m.relates_to": None}):
        assert core.thread_of(content) is None, content


def test_inbox_item_carries_the_thread():
    inbox = core.Inbox()
    inbox.add("!r", "t", "$e", thread="$root")
    inbox.add("!r", "i", "$f", {"id": "i", "mime": "image/png", "size": 3}, "$root")
    inbox.add("!r", "u", "$g")
    first, second, third = inbox.since(None, 0)
    assert first["thread"] == "$root" and second["thread"] == "$root" and second["image"]["id"] == "i"
    assert "thread" not in third


# --- images sent into a room (/image) ---------------------------------------------------------------------------------

# The first bytes of real files of 1024x768, written by Pillow 2026-11-15: enough for image_info, which reads only headers.
PNG_HEAD = bytes.fromhex("89504e470d0a1a0a0000000d494844520000040000000300080200000035d8825a00")
WEBP_LOSSY = bytes.fromhex("52494646b80500005745425056503820ac05000070a8009d012a000400033e31188c")
WEBP_LOSSLESS = bytes.fromhex("5249464644000000574542505650384c380000002fffc3bf0007508a2ad4a3ff0181")
WEBP_EXTENDED = bytes.fromhex("524946460406000057454250565038580a00000010000000ff0300ff0200414c5048")
# A JPEG as far as its frame header: SOI, an APP0 segment, a quantisation table, then SOF0 (or SOF2, progressive).
JPEG_HEAD = (bytes.fromhex("ffd8ffe000104a46494600010100000100010000") + b"\xff\xdb\x00\x43" + bytes(65)
             + bytes.fromhex("ffc0001108030004000301220002110103110100"))


def b64(data):
    return base64.b64encode(data).decode()


@pytest.mark.parametrize("data, mime", [(PNG_HEAD, "image/png"), (WEBP_LOSSY, "image/webp"), (WEBP_LOSSLESS, "image/webp"),
                                        (WEBP_EXTENDED, "image/webp"), (JPEG_HEAD, "image/jpeg"),
                                        (JPEG_HEAD.replace(b"\xff\xc0\x00\x11", b"\xff\xc2\x00\x11"), "image/jpeg")])
def test_image_info_reads_type_and_size_from_the_header(data, mime):
    assert core.image_info(data) == (mime, 1024, 768)


def test_image_info_of_a_cut_header_keeps_the_type_without_a_size():
    assert core.image_info(PNG_HEAD[:12]) == ("image/png", None, None)
    assert core.image_info(WEBP_LOSSY[:20]) == ("image/webp", None, None)
    assert core.image_info(JPEG_HEAD[:30]) == ("image/jpeg", None, None)
    # a table marker (DHT, C4) is no frame, and a segment length below 2 ends the search instead of looping
    assert core.image_info(b"\xff\xd8\xff\xc4\x00\x00" + bytes(20)) == ("image/jpeg", None, None)


@pytest.mark.parametrize("data", [b"", b"GIF89a" + bytes(30), b"<svg xmlns='http://www.w3.org/2000/svg'/>", b"RIFF" + bytes(4) + b"WAVE",
                                  bytes(40)])
def test_image_info_knows_nothing_else(data):
    assert core.image_info(data) is None


def test_parse_image_takes_the_type_from_the_bytes_and_names_the_file():
    picture = core.parse_image({"room": "!a:b", "data": b64(WEBP_LOSSY), "mime": "image/png"})
    assert picture == {"room": "!a:b", "data": WEBP_LOSSY, "mime": "image/webp", "width": 1024, "height": 768,
                       "name": "image.webp", "caption": None}
    picture = core.parse_image({"room": "!a:b", "data": b64(JPEG_HEAD), "name": "scene-2.jpg", "caption": "The inn at dusk"})
    assert (picture["name"], picture["caption"], picture["mime"]) == ("scene-2.jpg", "The inn at dusk", "image/jpeg")


def test_parse_image_refuses_bad_requests():
    good = {"room": "!a:b", "data": b64(PNG_HEAD)}
    for change, status in (({"data": ""}, 400), ({"data": 5}, 400), ({"data": "not base64!"}, 400),
                           ({"data": b64(b"GIF89a" + bytes(30))}, 400), ({"room": "x"}, 400),
                           ({"name": "a/b.png"}, 400), ({"name": ".hidden"}, 400), ({"name": "x" * 81}, 400), ({"name": 5}, 400),
                           ({"name": "a b.png"}, 400), ({"caption": ""}, 400), ({"caption": "  "}, 400), ({"caption": 5}, 400),
                           ({"caption": "x" * (core.CAPTION_MAX + 1)}, 413),
                           ({"data": b64(PNG_HEAD + bytes(core.IMAGE_MAX))}, 413)):
        with pytest.raises(core.Refused) as error:
            core.parse_image({**good, **change})
        assert error.value.status == status, change
    with pytest.raises(core.Refused):
        core.parse_image([])


def test_image_content_with_and_without_a_caption():
    picture = core.parse_image({"room": "!a:b", "data": b64(PNG_HEAD)})
    file = {"url": "mxc://example.org/x", "v": "v2"}
    assert core.image_content(picture, file) == {
        "msgtype": "m.image", "body": "image.png", "file": file,
        "info": {"mimetype": "image/png", "size": len(PNG_HEAD), "w": 1024, "h": 768}}
    captioned = core.image_content({**picture, "caption": "Mira"}, file)
    assert (captioned["body"], captioned["filename"]) == ("Mira", "image.png")
    assert core.caption_of(captioned) == "Mira" and core.caption_of(core.image_content(picture, file)) == ""
    assert "w" not in core.image_content({**picture, "width": None, "height": None}, file)["info"]
