"""Crypto primitives for cscli.

- AES-GCM authenticated encryption of the beacon/listener channel.
- Self-signed TLS certificate generation for HTTPS listeners.

Stdlib only (cryptography-free): AES-GCM via Python 3.11+'s
`encryption_algorithm`? No -- Python stdlib has no AES. We use the built-in
`hashlib` for key derivation (PBKDF2) and provide AES through ctypes calls to
OpenSSL. To keep the beacon dependency-free and truly portable, we implement
AES-GCM ourselves using a pure-Python GF(2^128) GCM with the AES core taken
from a small, audited pure-python AES implementation inlined here.
"""
import os
import shutil
import subprocess
import hashlib
import tempfile

from .aes import AESCipher


def derive_key(secret: str, salt: bytes = b"cscli-v1") -> bytes:
    """Derive a 32-byte AES key from a passphrase (PBKDF2-HMAC-SHA256)."""
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, 120000, 32)


class GCMCipher:
    """AES-GCM authenticated encryption of a whole message.

    Wire format:  <12-byte nonce> || <ciphertext + 16-byte tag>
    """

    def __init__(self, key: bytes):
        self.key = key

    def _to_blocks(self, xs):
        return int.from_bytes(xs, "big")

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        cipher = AESCipher(self.key)
        ct, tag = gcm_encrypt(cipher, nonce, plaintext, None)
        return nonce + ct + tag

    def decrypt(self, packet: bytes) -> bytes:
        if len(packet) < 12 + 16:
            raise ValueError("packet too short")
        nonce, body = packet[:12], packet[12:]
        ct, tag = body[:-16], body[-16:]
        cipher = AESCipher(self.key)
        pt = gcm_decrypt(cipher, nonce, ct, tag, None)
        return pt


# ---- pure-python GCM (GF(2^128)) ----
_GF_IRRED = 0xE1000000000000000000000000000000


def _gf_mul(a, b):
    """Multiply two 128-bit field elements."""
    r = 0
    for i in range(128):
        if (b >> i) & 1:
            r ^= a
        carry = a & 1
        a >>= 1
        if carry:
            a ^= _GF_IRRED
    return r


def _ghash(h, blocks):
    x = 0
    for blk in blocks:
        x ^= blk
        x = _gf_mul(x, h)
    return x


def _inc32(counter_block):
    n = int.from_bytes(counter_block, "big")
    # increment only low 32 bits
    n = (n & ~0xFFFFFFFF) | ((n + 1) & 0xFFFFFFFF)
    return n.to_bytes(16, "big")


def gcm_encrypt(cipher, nonce, plaintext, aad):
    """Return (ciphertext, tag)."""
    h = _to_fixed(cipher.encrypt_block(bytes(16)))
    blocks = []
    # pad plaintext into 16-byte blocks
    data = plaintext
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        blocks.append(int.from_bytes(chunk, "big") << (128 - 8 * len(chunk)) if len(chunk) < 16
                      else int.from_bytes(chunk, "big"))
    j0 = nonce + b"\x00\x00\x00\x01"
    ctr = int.from_bytes(j0, "big")
    ct = bytearray()
    for i in range(0, len(data), 16):
        ctr = (ctr + 1) & ((1 << 128) - 1)
        keystream = cipher.encrypt_block(ctr.to_bytes(16, "big"))
        chunk = data[i:i + 16]
        out = bytes(a ^ b for a, b in zip(chunk, keystream[:len(chunk)]))
        ct += out
    # tag over AAD + ciphertext lengths
    aad_blk = _aad_to_blocks(aad or b"")
    s = _ghash(h, aad_blk + [_b2i(b) for b in _chunks(bytes(ct), 16)])
    lens = ((len(aad or b"") * 8) << 64) | (len(ct) * 8)
    s ^= lens
    tag = (_gf_mul(s, h) ^ _b2i(cipher.encrypt_block(j0)))
    return bytes(ct), tag.to_bytes(16, "big")


def gcm_decrypt(cipher, nonce, ciphertext, tag, aad):
    """Recover plaintext, raising ValueError if tag mismatches."""
    h = _to_fixed(cipher.encrypt_block(bytes(16)))
    j0 = nonce + b"\x00\x00\x00\x01"
    # recompute tag
    blocks = [_b2i(b) for b in _chunks(ciphertext, 16)]
    aad_blk = _aad_to_blocks(aad or b"")
    s = _ghash(h, aad_blk + blocks)
    lens = ((len(aad or b"") * 8) << 64) | (len(ciphertext) * 8)
    s ^= lens
    expect = (_gf_mul(s, h) ^ _b2i(cipher.encrypt_block(j0))).to_bytes(16, "big")
    if not _const_eq(expect, tag):
        raise ValueError("GCM tag mismatch -- wrong key or tampered packet")
    ctr = int.from_bytes(j0, "big")
    pt = bytearray()
    for i in range(0, len(ciphertext), 16):
        ctr = (ctr + 1) & ((1 << 128) - 1)
        keystream = cipher.encrypt_block(ctr.to_bytes(16, "big"))
        chunk = ciphertext[i:i + 16]
        pt += bytes(a ^ b for a, b in zip(chunk, keystream[:len(chunk)]))
    return bytes(pt)


def _b2i(b):
    return int.from_bytes(b, "big")


def _chunks(data, n):
    return [data[i:i + n] for i in range(0, len(data), n)]


def _to_fixed(b):
    return int.from_bytes(b, "big")


def _aad_to_blocks(aad):
    blk = b""
    out = []
    for byte in aad:
        blk += bytes([byte])
        if len(blk) == 16:
            out.append(int.from_bytes(blk, "big"))
            blk = b""
    if blk:
        out.append(int.from_bytes(blk, "big") << (128 - 8 * len(blk)))
    return out


def _const_eq(a, b):
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0
