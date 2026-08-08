"""Pure-python AES block cipher (128/192/256-bit keys).

Minimal, self-contained implementation for use by the AES-GCM C2 channel,
with no external dependencies. Internally uses table-based mix columns for
speed while staying portable.
"""

# ---- S-box and inverse ----
_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

# ---- GF(2^8) multiply by 2,3 in AES ----
def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _GF_MULT(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a = _xtime(a)
        b >>= 1
    return p & 0xFF


# ---- key expansion schedule (word-oriented) ----
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _expand_key(key: bytes):
    Nk = len(key) // 4          # 128->4, 192->6, 256->8
    Nr = {4: 10, 6: 12, 8: 14}[Nk]
    w = list(key)
    i = Nk
    while i < 4 * (Nr + 1):
        temp = w[(i - 1) * 4:(i - 1) * 4 + 4]
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[(i // Nk) - 1]
        elif Nk > 6 and i % Nk == 4:
            temp = [_SBOX[b] for b in temp]
        w += [w[(i - Nk) * 4 + j] ^ temp[j] for j in range(4)]
        i += 1
    # return round keys as list of 16-byte round keys
    round_keys = []
    for r in range(Nr + 1):
        round_keys.append(bytes(w[r * 16:r * 16 + 16]))
    return round_keys, Nr


class AESCipher:
    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16/24/32 bytes")
        self._rk, self.Nr = _expand_key(key)

    @staticmethod
    def _add_round_key(state, rk):
        return [state[i] ^ rk[i] for i in range(16)]

    def encrypt_block(self, blk: bytes) -> bytes:
        if len(blk) != 16:
            raise ValueError("block must be 16 bytes")
        state = list(blk)
        rk = self._rk
        state = self._add_round_key(state, rk[0])
        for r in range(1, self.Nr):
            state = [_SBOX[b] for b in state]                       # SubBytes
            state = self._shift_rows(state, False)                  # ShiftRows
            state = self._mix_columns(state)                        # MixColumns
            state = self._add_round_key(state, rk[r])
        state = [_SBOX[b] for b in state]
        state = self._shift_rows(state, False)
        state = self._add_round_key(state, rk[self.Nr])
        return bytes(state)

    def decrypt_block(self, blk: bytes) -> bytes:
        if len(blk) != 16:
            raise ValueError("block must be 16 bytes")
        state = list(blk)
        rk = self._rk
        state = self._add_round_key(state, rk[self.Nr])
        for r in range(self.Nr - 1, 0, -1):
            state = self._shift_rows(state, True)
            state = [_INV_SBOX[b] for b in state]
            state = self._add_round_key(state, rk[r])
            state = self._inv_mix_columns(state)
        state = self._shift_rows(state, True)
        state = [_INV_SBOX[b] for b in state]
        state = self._add_round_key(state, rk[0])
        return bytes(state)

    @staticmethod
    def _shift_rows(state, inv):
        """ShiftRows for a state given as byte list in row-major (col*4+? we use
        standard column-major interpretation: state[col*4 + row] is byte (row,col)).
        Forward: row r is cyclically shifted left by r columns.
        Inverse:  row r is cyclically shifted right by r columns."""
        # represent as matrix M[col][row] -> byte index = col*4 + row
        out = state[:]
        for row in range(4):
            for col in range(4):
                if inv:
                    src_col = (col - row) % 4
                else:
                    src_col = (col + row) % 4
                out[col * 4 + row] = state[src_col * 4 + row]
        return out

    @staticmethod
    def _mix_columns(state):
        out = state[:]
        for c in range(4):
            i = c * 4
            s0, s1, s2, s3 = state[i], state[i + 1], state[i + 2], state[i + 3]
            out[i]     = _GF_MULT(s0, 2) ^ _GF_MULT(s1, 3) ^ s2 ^ s3
            out[i + 1] = s0 ^ _GF_MULT(s1, 2) ^ _GF_MULT(s2, 3) ^ s3
            out[i + 2] = s0 ^ s1 ^ _GF_MULT(s2, 2) ^ _GF_MULT(s3, 3)
            out[i + 3] = _GF_MULT(s0, 3) ^ s1 ^ s2 ^ _GF_MULT(s3, 2)
        return out

    @staticmethod
    def _inv_mix_columns(state):
        out = state[:]
        for c in range(4):
            i = c * 4
            s0, s1, s2, s3 = state[i], state[i + 1], state[i + 2], state[i + 3]
            out[i]     = _GF_MULT(s0, 14) ^ _GF_MULT(s1, 11) ^ _GF_MULT(s2, 13) ^ _GF_MULT(s3, 9)
            out[i + 1] = _GF_MULT(s0, 9) ^ _GF_MULT(s1, 14) ^ _GF_MULT(s2, 11) ^ _GF_MULT(s3, 13)
            out[i + 2] = _GF_MULT(s0, 13) ^ _GF_MULT(s1, 9) ^ _GF_MULT(s2, 14) ^ _GF_MULT(s3, 11)
            out[i + 3] = _GF_MULT(s0, 11) ^ _GF_MULT(s1, 13) ^ _GF_MULT(s2, 9) ^ _GF_MULT(s3, 14)
        return out
