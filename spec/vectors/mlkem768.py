"""ML-KEM-768 (FIPS 203), deterministic, pure Python: test-vector generation only.

KeyGen_internal(d, z) and Encaps_internal(ek, m) are exposed so the vectors are reproducible.
The 64-byte seed d || z is the form Go's crypto/mlkem NewDecapsulationKey768 takes; the expanded
decapsulation key (2400 bytes) is the form the SDK's pqcrypto backend takes. Never use this
module for anything but vectors (it is slow and not constant time). It was checked against
pqcrypto's ML-KEM-768 both ways.
"""

import hashlib

N, Q, K, ETA1, ETA2, DU, DV = 256, 3329, 3, 2, 2, 10, 4


def _bitrev7(i):
    return int(f"{i:07b}"[::-1], 2)


ZETAS = [pow(17, _bitrev7(i), Q) for i in range(128)]
GAMMAS = [pow(17, 2 * _bitrev7(i) + 1, Q) for i in range(128)]


def H(data):
    return hashlib.sha3_256(data).digest()


def G(data):
    out = hashlib.sha3_512(data).digest()
    return out[:32], out[32:]


def J(data):
    return hashlib.shake_256(data).digest(32)


def PRF(eta, s, b):
    return hashlib.shake_256(s + bytes([b])).digest(64 * eta)


def sample_ntt(seed):
    length = 840
    while True:
        stream = hashlib.shake_128(seed).digest(length)
        coeffs, pos = [], 0
        while len(coeffs) < N and pos + 3 <= len(stream):
            c0, c1, c2 = stream[pos], stream[pos + 1], stream[pos + 2]
            pos += 3
            d1 = c0 + 256 * (c1 % 16)
            d2 = (c1 // 16) + 16 * c2
            if d1 < Q:
                coeffs.append(d1)
            if d2 < Q and len(coeffs) < N:
                coeffs.append(d2)
        if len(coeffs) == N:
            return coeffs
        length *= 2


def cbd(eta, data):
    bits = [(data[i // 8] >> (i % 8)) & 1 for i in range(len(data) * 8)]
    out = []
    for i in range(N):
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        out.append((x - y) % Q)
    return out


def ntt(f):
    f = list(f)
    i, length = 1, 128
    while length >= 2:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[i]
            i += 1
            for j in range(start, start + length):
                t = zeta * f[j + length] % Q
                f[j + length] = (f[j] - t) % Q
                f[j] = (f[j] + t) % Q
        length //= 2
    return f


def intt(f):
    f = list(f)
    i, length = 127, 2
    while length <= 128:
        for start in range(0, N, 2 * length):
            zeta = ZETAS[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = zeta * (f[j + length] - t) % Q
        length *= 2
    return [x * 3303 % Q for x in f]


def mul_ntt(f, g):
    h = [0] * N
    for i in range(128):
        a0, a1, b0, b1 = f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]
        h[2 * i] = (a0 * b0 + a1 * b1 * GAMMAS[i]) % Q
        h[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
    return h


def add(f, g):
    return [(a + b) % Q for a, b in zip(f, g)]


def sub(f, g):
    return [(a - b) % Q for a, b in zip(f, g)]


def encode(d, f):
    bits = []
    for x in f:
        bits.extend((x >> j) & 1 for j in range(d))
    return bytes(sum(bits[8 * i + j] << j for j in range(8)) for i in range(len(bits) // 8))


def decode(d, data):
    bits = [(data[i // 8] >> (i % 8)) & 1 for i in range(len(data) * 8)]
    m = Q if d == 12 else (1 << d)
    return [sum(bits[d * i + j] << j for j in range(d)) % m for i in range(N)]


def compress(d, f):
    return [((x << d) + Q // 2) // Q % (1 << d) for x in f]


def decompress(d, f):
    return [(y * Q + (1 << (d - 1))) >> d for y in f]


def _matrix(rho):
    return [[sample_ntt(rho + bytes([j, i])) for j in range(K)] for i in range(K)]


def pke_keygen(d):
    rho, sigma = G(d + bytes([K]))
    a = _matrix(rho)
    n = 0
    s, e = [], []
    for _ in range(K):
        s.append(cbd(ETA1, PRF(ETA1, sigma, n)))
        n += 1
    for _ in range(K):
        e.append(cbd(ETA1, PRF(ETA1, sigma, n)))
        n += 1
    s_hat = [ntt(x) for x in s]
    e_hat = [ntt(x) for x in e]
    t_hat = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = add(acc, mul_ntt(a[i][j], s_hat[j]))
        t_hat.append(add(acc, e_hat[i]))
    ek = b"".join(encode(12, x) for x in t_hat) + rho
    dk = b"".join(encode(12, x) for x in s_hat)
    return ek, dk


def pke_encrypt(ek, m, r):
    t_hat = [decode(12, ek[384 * i : 384 * (i + 1)]) for i in range(K)]
    rho = ek[384 * K :]
    a = _matrix(rho)
    n = 0
    y, e1 = [], []
    for _ in range(K):
        y.append(cbd(ETA1, PRF(ETA1, r, n)))
        n += 1
    for _ in range(K):
        e1.append(cbd(ETA2, PRF(ETA2, r, n)))
        n += 1
    e2 = cbd(ETA2, PRF(ETA2, r, n))
    y_hat = [ntt(x) for x in y]
    u = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = add(acc, mul_ntt(a[j][i], y_hat[j]))
        u.append(add(intt(acc), e1[i]))
    mu = decompress(1, decode(1, m))
    acc = [0] * N
    for j in range(K):
        acc = add(acc, mul_ntt(t_hat[j], y_hat[j]))
    v = add(add(intt(acc), e2), mu)
    c1 = b"".join(encode(DU, compress(DU, x)) for x in u)
    c2 = encode(DV, compress(DV, v))
    return c1 + c2


def pke_decrypt(dk, c):
    c1, c2 = c[: 32 * DU * K], c[32 * DU * K :]
    u = [decompress(DU, decode(DU, c1[32 * DU * i : 32 * DU * (i + 1)])) for i in range(K)]
    v = decompress(DV, decode(DV, c2))
    s_hat = [decode(12, dk[384 * i : 384 * (i + 1)]) for i in range(K)]
    acc = [0] * N
    for j in range(K):
        acc = add(acc, mul_ntt(s_hat[j], ntt(u[j])))
    w = sub(v, intt(acc))
    return encode(1, compress(1, w))


def keygen(d, z):
    """(ek 1184 bytes, dk 2400 bytes) from the 64-byte seed d || z (FIPS 203 KeyGen_internal)."""
    assert len(d) == 32 and len(z) == 32
    ek, dk_pke = pke_keygen(d)
    return ek, dk_pke + ek + H(ek) + z


def encaps(ek, m):
    """(shared key 32 bytes, ciphertext 1088 bytes) for message m (FIPS 203 Encaps_internal)."""
    assert len(ek) == 1184 and len(m) == 32
    shared, r = G(m + H(ek))
    return shared, pke_encrypt(ek, m, r)


def decaps(dk, c):
    """The shared key (FIPS 203 Decaps_internal, implicit rejection included)."""
    assert len(dk) == 2400 and len(c) == 1088
    dk_pke, ek = dk[: 384 * K], dk[384 * K : 768 * K + 32]
    h, z = dk[768 * K + 32 : 768 * K + 64], dk[768 * K + 64 :]
    m = pke_decrypt(dk_pke, c)
    shared, r = G(m + h)
    rejected = J(z + c)
    return shared if pke_encrypt(ek, m, r) == c else rejected
