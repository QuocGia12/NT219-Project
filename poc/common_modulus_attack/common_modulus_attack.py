from math import gcd
from Crypto.Util.number import inverse

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def common_modulus_attack(n, e1, e2, c1, c2):
    g, a, b = egcd(e1, e2)
    if g != 1:
        return None
    if a < 0:
        c1 = inverse(c1, n)
        a = -a
    part1 = pow(c1, a, n)

    if b < 0:
        c2 = inverse(c2, n)
        b = -b
    part2 = pow(c2, b, n)

    return (part1 * part2) % n
