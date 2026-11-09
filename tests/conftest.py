"""mautrix.crypto imports python-olm (bindings to the C library libolm) when the package is imported, which the off-line
test environment does not have. The tests and the plugin need only the submodule mautrix.crypto.attachments (AES-CTR
attachment encryption, pure Python), so without a working olm the package is replaced by an empty one that still lets that
submodule be found. On the real maubot (LXC 123) the genuine package is used, because the bot's account is encrypted.
Needs pycryptodome and unpaddedbase64 either way."""
import importlib.util
import os
import sys
import types

try:
    import mautrix.crypto  # noqa: F401
except ImportError:
    for name in [n for n in sys.modules if n == "mautrix.crypto" or n.startswith("mautrix.crypto.")]:
        del sys.modules[name]
    base = importlib.util.find_spec("mautrix").submodule_search_locations[0]
    stub = types.ModuleType("mautrix.crypto")
    stub.__path__ = [os.path.join(base, "crypto")]
    sys.modules["mautrix.crypto"] = stub
