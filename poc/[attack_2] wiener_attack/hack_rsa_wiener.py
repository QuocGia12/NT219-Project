#!/usr/bin/env python3

import math

# paste e, n, c tu challenge_file.py vao day
e = 9487283465375795596376911764363815112802766223888581137251279249452501175778700502353789731587966639165198866132773367586393933382515661543162260274099067
n = 12563472365225756629734255948093547051199020714357781959193236185182744502200884873061807563335342297779823905666868444440938029834429867568914404808571093
c = 3674795283852474345982939959129815939995555294247100955711954935286609996471131419761692379939660698552579408225402677456474901076214019304521906352837737

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

def int_to_bytes(m):
    if m == 0:
        return b""
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, "big")

def main():
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
    print("    p bitlen:", p.bit_length())
    print("    q bitlen:", q.bit_length())
    print("    d:", d)
    # giai ma
    m = pow(c, d, n)
    b = int_to_bytes(m)
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
