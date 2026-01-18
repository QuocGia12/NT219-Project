from fractions import Fraction
from math import isqrt

def continued_fraction(n, d):
    cf = []
    while d:
        q = n // d
        cf.append(q)
        n, d = d, n - q * d
    return cf

def convergents(cf):
    convs = []
    for i in range(len(cf)):
        frac = Fraction(cf[i], 1)
        for j in range(i - 1, -1, -1):
            frac = cf[j] + 1 / frac
        convs.append((frac.numerator, frac.denominator))
    return convs

def is_square(n):
    r = isqrt(n)
    return r * r == n

def wiener_attack(e, n):
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        discr = s * s - 4 * n
        if discr >= 0 and is_square(discr):
            return d
    return None
