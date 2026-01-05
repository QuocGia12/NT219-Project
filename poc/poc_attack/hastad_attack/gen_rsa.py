from Crypto.Util.number import getPrime, bytes_to_long
import random

def gen_instances(e, k, n_bits=1024):
    m = random.randrange(2, 2**(n_bits//4))
    instances = []

    for _ in range(k):
        p = getPrime(n_bits // 2)
        q = getPrime(n_bits // 2)
        n = p * q
        c = pow(m, e, n)
        instances.append((n, c))

    return m, instances
