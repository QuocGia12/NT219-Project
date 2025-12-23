#!/usr/bin/env python3

import math
from sympy import isprime 
from random import randint
from Cryptodome.Util.number import getPrime, bytes_to_long, long_to_bytes

def cont_frac(numer, denom):
    # tra ve danh sach phan so lien tuc a0,a1,...
    a = []
    while denom:
        q = numer // denom
        a.append(q)
        numer, denom = denom, numer - q*denom
    return a

def convergents_from_cf(cf):
    # tra ve danh sach (p,q) la cac convergents tu phan so lien tuc
    convs = []
    for i in range(len(cf)):
        p0, q0 = 1, 0
        p1, q1 = cf[0], 1
        if i == 0:
            convs.append((p1, q1))
            continue
        for a in cf[1:i+1]:
            p2 = a*p1 + p0
            q2 = a*q1 + q0
            p0, q0, p1, q1 = p1, q1, p2, q2
        convs.append((p1, q1))
    return convs

def is_perfect_square(n):
    if n < 0:
        return False
    t = math.isqrt(n)
    return t*t == n

def wiener_attack(n, e):
    cf = cont_frac(e, n)
    convs = convergents_from_cf(cf)
    for k, d in convs:
        if k == 0:
            continue
        # dieu kien co hoi
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s*s - 4*n
        if disc >= 0 and is_perfect_square(disc):
            t = math.isqrt(disc)
            p = (s + t) // 2
            q = (s - t) // 2
            if p > 1 and q > 1 and p*q == n:
                return (int(p), int(q), int(d))
    return None


def iroot4(n):
    lo, hi = 0, 1 << ((n.bit_length() + 3) // 4)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid**4 <= n:
            lo = mid + 1
        else:
            hi = mid
    return lo - 1

def VulnServer(pt): # mô phỏng server thực hiện encrypt RSA với d < 1/3 * n^0.25 
    p = getPrime(1024)
    q = getPrime(1024)
    n = p*q 
    phi = (p-1)*(q-1)
    d = 4
    while(isprime(d)==0): 
        d = randint(100, (iroot4(n))//3)
    e = pow(d, -1, phi)
    m = bytes_to_long(pt)
    ct = pow(m, e, n)

    return ct, e, n 
    

def main():
    pt = input("Nhap plaintext: ").encode()
    c, e, n = VulnServer(pt)

    print("[*] Loaded public values:")
    print("    n bitlen:", n.bit_length())
    print("    e:", e)
    print("    cipher len(dec):", len(str(c)))
    print("[*] Running Wiener attack...")
    res = wiener_attack(n, e)
    if res is None:
        print("[!] Wiener attack failed: khong tim duoc d tu convergents.")
        return
    p, q, d = res
    print("[+] Recovered p,q,d:")
    print("    p:", p)
    print("    q:", q)
    print("    d:", d)
    # giai ma
    m = pow(c, d, n)
    b = long_to_bytes(m)
    # co the la chuoi ascii, neu decode khong duoc se in hex de debug
    try:
        s = b.decode("utf-8")
        print("[+] Decrypted message (utf-8):")
        print(s)
    except Exception:
        print("[+] Decrypted bytes (hex):")
        print(b.hex())
        print("[+] Raw bytes repr:", b)

if __name__ == "__main__":
    main()
