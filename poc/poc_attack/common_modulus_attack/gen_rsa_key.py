from Crypto.Util.number import getPrime, bytes_to_long, inverse
from math import gcd
import random

def gen_common_modulus_rsa(n_bits=1024):
    p = getPrime(n_bits // 2)
    q = getPrime(n_bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    while True:
        e1 = getPrime(100)
        e2 = getPrime(100)
        if gcd(e1, e2) == 1 and gcd(e1, phi) == 1 and gcd(e2, phi) == 1:
            break

    d1 = inverse(e1, phi)
    d2 = inverse(e2, phi)

    m = random.randrange(2, n)
    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)

    return n, e1, e2, c1, c2, m
