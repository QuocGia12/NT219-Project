from Cryptodome.Util.number import getPrime

from hashlib import sha3_256
from sympy.ntheory.modular import crt

from math import gcd 

p=getPrime(1024)
q=getPrime(1024)
N=p*q 
e=65537


def BugServer(m, fault):   #m: bytes, fault: 0 or 1 
    h=sha3_256(m).digest()
    h=int.from_bytes(h, 'big')
    dp=pow(e, -1, p-1)
    dq=pow(e, -1, q-1)
    s1=pow(h, dp, p)
    if fault==1: 
        s1-=100 # mô phỏng lỗi 
    s2=pow(h, dq, q)

    s, mod=crt([p, q], [s1, s2])
    return s

def attack(): 
    m = b"test"
    fault = 0
    s=BugServer(m, fault)
    fault = 1 
    s_fault = BugServer(m, fault)
    q_recover=gcd(s-s_fault, N)

    p_recover=N//q_recover

    print(f"p: {p}")
    print(f"q: {q}")
    print(f"p_recover: {p_recover}")
    print(f"q_recover: {q_recover}")


if __name__=='__main__': 
    attack()


    

