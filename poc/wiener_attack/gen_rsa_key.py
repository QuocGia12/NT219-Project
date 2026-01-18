from Crypto.Util.number import getPrime, inverse, GCD
import random

def gen_weak_rsa(n_bits=1024, d_bits=128):
    p = getPrime(n_bits // 2)
    q = getPrime(n_bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    while True:
        d = random.getrandbits(d_bits)
        if d > 1 and GCD(d, phi) == 1:
            break

    e = inverse(d, phi)
    return n, e, d
