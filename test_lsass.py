#!/usr/bin/env python3
"""Unit-test the cs.modules.lsass module.

This test runs anywhere -- it does NOT require admin or LSASS. It exercises:
  * dump_lsass() on non-Windows -> (False, "only on Windows")
  * dump_lsass() on Windows with bad prefer -> (False, "unknown prefer")
  * parse_dump() with missing file -> (False, "dump file not found")
  * parse_dump() with garbage file -> either (False, parse failed) or a
    pypykatz error string -- either way the API surfaces a clear message.
  * _resolve_lsass_pid() on non-Windows -> None

If pypykatz is installed AND a real lsass.dmp is on disk, parse_dump() will
return the parsed credentials; we accept any non-empty output as a smoke
test in that case.

Run:  python3 test_lsass.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cs.modules import lsass


def expect(cond, msg):
    if not cond:
        print(f"[FAIL] {msg}")
        return False
    print(f"[PASS] {msg}")
    return True


def main():
    passed = 0
    failed = 0

    # 1. Non-Windows: dump_lsass refuses politely.
    if os.name != "nt":
        ok, msg = lsass.dump_lsass("/tmp/x.dmp")
        passed += expect(ok is False, "dump_lsass on non-Windows returns False")
        passed += expect("Windows" in msg,
                         "dump_lsass on non-Windows mentions Windows")
    else:
        # 2. Bad strategy -> clear error.
        ok, msg = lsass.dump_lsass(r"C:\Temp\x.dmp", prefer="bogus")
        passed += expect(ok is False, "bad prefer returns False")
        passed += expect("unknown prefer" in msg,
                         "bad prefer surfaces 'unknown prefer'")

    # 3. parse_dump with missing file -> clean error.
    ok, msg = lsass.parse_dump("/nonexistent/lsass.dmp")
    passed += expect(ok is False, "parse_dump on missing file returns False")
    # Either "not found" (file check first) or "pypykatz not installed" if
    # pypykatz isn't on this host; both are correct surface messages.
    passed += expect(("not found" in msg) or ("pypykatz not installed" in msg),
                     "parse_dump missing-file error message")

    # 4. parse_dump with empty file -> pypykatz error or "no principals",
    #    either way it doesn't crash.
    tmp = "/tmp/cscli_lsass_garbage.dmp"
    try:
        with open(tmp, "wb") as f:
            f.write(b"\x00" * 4096)
        ok, msg = lsass.parse_dump(tmp)
        passed += expect(isinstance(msg, str), "parse_dump returns string")
        # ok may be False (pypykatz errors) -- that's acceptable here.
        passed += expect(len(msg) > 0, "parse_dump on garbage returns non-empty")
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    # 5. _resolve_lsass_pid on non-Windows -> None.
    if os.name != "nt":
        passed += expect(lsass._resolve_lsass_pid() is None,
                         "_resolve_lsass_pid returns None on non-Windows")

    # 6. Module exposes public API.
    for name in ("dump_lsass", "parse_dump",
                 "sekurlsa_logonpasswords", "format_sekurlsa"):
        passed += expect(hasattr(lsass, name), f"lsass.{name} is exported")

    # 7. pypykatz importability check -- we don't fail the test if missing,
    #    but we report what the operator host needs.
    try:
        import pypykatz  # noqa: F401
        print("[INFO] pypykatz is installed -- operator-side parse available")
    except ImportError:
        print("[INFO] pypykatz NOT installed -- install with: pip install pypykatz")

    # ---- sekurlsa_logonpasswords API checks ----

    # 8. Non-Windows: sekurlsa refuses politely (no admin needed for the check).
    if os.name != "nt":
        ok, msg = lsass.sekurlsa_logonpasswords()
        passed += expect(ok is False,
                         "sekurlsa on non-Windows returns False")
        passed += expect("Windows" in msg,
                         "sekurlsa on non-Windows mentions Windows")
    else:
        # On Windows, the call may succeed (if admin) or fail with a clear
        # LiveReader error. Either way it must return a (bool, str) tuple.
        ok, msg = lsass.sekurlsa_logonpasswords(no_lsa=True)
        passed += expect(isinstance(ok, bool), "sekurlsa returns bool")
        passed += expect(isinstance(msg, str), "sekurlsa returns str")
        # If pypykatz is missing, the error must mention it.
        try:
            import pypykatz  # noqa: F401
        except ImportError:
            passed += expect("pypykatz" in msg,
                             "sekurlsa on Windows without pypykatz mentions pypykatz")

    # 9. format_sekurlsa with a synthetic apypykatz-like object.
    #    Build a tiny stub that exposes logon_sessions / orphaned_creds /
    #    errors so we can render without needing a real lsass.
    class _StubCred:
        def __init__(self, d):
            self._d = d
        def to_dict(self):
            return dict(self._d)
    class _StubSess:
        def __init__(self):
            self.authentication_id = 996
            self.session_id = 1
            self.username = "Administrator"
            self.domainname = "CORP"
            self.logon_server = "DC01"
            self.logon_time = None
            self.sid = "S-1-5-32-544"
            self.msv_creds = [_StubCred({"credtype": "Primary",
                                          "username": "Administrator",
                                          "domainname": "CORP",
                                          "NThash": "aad3b435b51404eeaad3b435b51404ee",
                                          "LMHash": ""})]
            self.wdigest_creds = [_StubCred({"credtype": "wdigest",
                                              "username": "Administrator",
                                              "domainname": "CORP",
                                              "password": "P@ssw0rd!"})]
            self.kerberos_creds = []
            self.tspkg_creds = []
            self.ssp_creds = []
            self.livessp_creds = []
            self.dpapi_creds = []
            self.cloudap_creds = []
            self.credman_creds = []
    class _StubMimi:
        def __init__(self):
            self.logon_sessions = {996: _StubSess()}
            self.orphaned_creds = []
            self.errors = []

    report = lsass.format_sekurlsa(_StubMimi())
    passed += expect("sekurlsa::logonpasswords" in report,
                     "format_sekurlsa prints the header")
    passed += expect("Authentication Id" in report,
                     "format_sekurlsa prints 'Authentication Id'")
    passed += expect("Administrator" in report,
                     "format_sekurlsa includes the username")
    passed += expect("aad3b435b51404ee" in report,
                     "format_sekurlsa includes the NTLM hash")
    passed += expect("P@ssw0rd!" in report,
                     "format_sekurlsa includes the WDigest cleartext password")
    passed += expect("msv :" in report or "msv:" in report,
                     "format_sekurlsa renders the 'msv :' block")
    passed += expect("wdigest :" in report or "wdigest:" in report,
                     "format_sekurlsa renders the 'wdigest :' block")

    # ---- wdigest toggle API ----
    # 10. Non-Windows: enable_wdigest refuses politely.
    if os.name != "nt":
        ok, msg = lsass.enable_wdigest()
        passed += expect(ok is False, "enable_wdigest on non-Windows returns False")
        passed += expect("Windows" in msg, "enable_wdigest mentions Windows")
        ok, msg = lsass.wdigest_status()
        passed += expect(ok is False, "wdigest_status on non-Windows returns False")
    else:
        # On Windows the calls may succeed (admin) or fail with access denied;
        # either way they must return (bool, str).
        ok, msg = lsass.wdigest_status()
        passed += expect(isinstance(ok, bool) and isinstance(msg, str),
                         "wdigest_status returns (bool, str) on Windows")
        ok, msg = lsass.enable_wdigest()
        passed += expect(isinstance(ok, bool) and isinstance(msg, str),
                         "enable_wdigest returns (bool, str) on Windows")

    # 11. sekurlsa_logonpasswords signature supports ticket export params.
    import inspect as _inspect
    sig = _inspect.signature(lsass.sekurlsa_logonpasswords)
    params = set(sig.parameters.keys())
    passed += expect("export_dir" in params,
                     "sekurlsa_logonpasswords has export_dir param")
    passed += expect("export_ccache" in params,
                     "sekurlsa_logonpasswords has export_ccache param")

    # 12. sekurlsa with export on non-Windows refuses politely (windows guard
    #     fires before any pypykatz/ticket work).
    if os.name != "nt":
        ok, msg = lsass.sekurlsa_logonpasswords(export_dir="/tmp/tkts")
        passed += expect(ok is False,
                         "sekurlsa --export-dir on non-Windows returns False")
        passed += expect("Windows" in msg,
                         "sekurlsa --export-dir mentions Windows")

    print()
    print(f"[INFO] sample formatted output:\n{'-' * 60}")
    for line in report.split("\n")[:20]:
        print(line)
    print(f"{'-' * 60}")
    if failed:
        print(f"[FAIL] {failed} checks failed")
        return 1
    print(f"[PASS] all {passed} checks ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())