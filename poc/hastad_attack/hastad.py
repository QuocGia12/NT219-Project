from math import prod
from Crypto.Util.number import inverse

# Tính căn bậc e của x 
def integer_root(x, e):
    low, high = 0, x
    while low <= high:
        mid = (low + high) // 2
        mid_pow = mid ** e
        if mid_pow == x:
            return mid, 1
        elif mid_pow < x:
            low = mid + 1
        else:
            high = mid - 1 
    if (high**e==x): 
        return high, 1 
    else: 
        return high, 0

def crt(ns, cs):
    N = prod(ns)
    result = 0
    for n, c in zip(ns, cs):
        Ni = N // n
        inv = inverse(Ni, n)
        result += c * Ni * inv
    return result % N

def hastad_attack(ns, cs, e):
    C = crt(ns, cs)
    m_root, exact = integer_root(C, e)
    if exact:
        return m_root
    return None
