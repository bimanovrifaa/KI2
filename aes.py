import os


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _make_sbox():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09
        sbox[p] = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


SBOX = _make_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
MIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
INV_MIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def expand_key(key):
    if len(key) != 16:
        raise ValueError("key harus tepat 16 karakter ASCII")
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(11)]


def _add_round_key(s, rk):
    return [a ^ b for a, b in zip(s, rk)]


def _sub_bytes(s, box):
    return [box[b] for b in s]


def _shift_rows(s):
    return [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]


def _inv_shift_rows(s):
    return [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]


def _mix_columns(s, m):
    out = []
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            v = 0
            for k in range(4):
                v ^= _gmul(m[r][k], col[k])
            out.append(v)
    return out


def encrypt_block(block, rks):
    s = _add_round_key(list(block), rks[0])
    for rnd in range(1, 10):
        s = _sub_bytes(s, SBOX)
        s = _shift_rows(s)
        s = _mix_columns(s, MIX)
        s = _add_round_key(s, rks[rnd])
    s = _sub_bytes(s, SBOX)
    s = _shift_rows(s)
    s = _add_round_key(s, rks[10])
    return bytes(s)


def decrypt_block(block, rks):
    s = _add_round_key(list(block), rks[10])
    for rnd in range(9, 0, -1):
        s = _inv_shift_rows(s)
        s = _sub_bytes(s, INV_SBOX)
        s = _add_round_key(s, rks[rnd])
        s = _mix_columns(s, INV_MIX)
    s = _inv_shift_rows(s)
    s = _sub_bytes(s, INV_SBOX)
    s = _add_round_key(s, rks[0])
    return bytes(s)


def cbc_encrypt(key, data):
    rks = expand_key(key)
    pad = 16 - len(data) % 16
    data = data + bytes([pad]) * pad
    iv = os.urandom(16)
    prev = iv
    out = [iv]
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = encrypt_block(blk, rks)
        out.append(prev)
    return b"".join(out)


def cbc_decrypt(key, blob):
    if len(blob) < 32 or len(blob) % 16:
        raise ValueError("panjang ciphertext tidak valid")
    rks = expand_key(key)
    out = b""
    for i in range(16, len(blob), 16):
        blk = blob[i:i + 16]
        plain = decrypt_block(blk, rks)
        out += bytes(a ^ b for a, b in zip(plain, blob[i - 16:i]))
    pad = out[-1]
    if pad < 1 or pad > 16 or out[-pad:] != bytes([pad]) * pad:
        raise ValueError("padding tidak valid (key salah?)")
    return out[:-pad]


def encrypt_hex(key_ascii, text_ascii):
    return cbc_encrypt(key_ascii.encode("ascii"), text_ascii.encode("ascii")).hex()


def decrypt_hex(key_ascii, hex_str):
    return cbc_decrypt(key_ascii.encode("ascii"), bytes.fromhex(hex_str)).decode("ascii")
