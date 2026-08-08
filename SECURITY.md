# Security

## Intended use
cscli is a demonstration of C2 architecture for **authorized** security testing,
red-team exercises, and education. It must only ever be run against systems you
own or have explicit written permission to test. Unauthorised deployment of an
implant is unlawful and unethical, and is not supported by this project.

## What this project will not do
- It does **not** ship a working Mimikatz / LSASS memory-scraper, and does not
  recover account passwords or hashes from process memory.
- The `creds` beacon command only reports credentials that the operating system
  already exposes to the calling user through documented APIs (e.g. Windows
  Credential Manager, the user's environment, the session kernel keyring). It
  is gated and documented accordingly.
- Windows remote-thread injection routines are gated to Windows-only hosts and
  refuse to run elsewhere.

## Reporting issues
Do **not** report abuse or use of this tool anywhere. For code bugs, open a
normal issue on the repository. Do not disclose real (unauthorised) targets —
this project will not assist with or acknowledge such activity.

## Operational note
The AES-GCM channel key and TLS certificate are for integrity/confidentiality of
the C2 channel, not a substitute for authorisation. Only test systems you are
allowed to test.
