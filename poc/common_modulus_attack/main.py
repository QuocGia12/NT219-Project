from Cryptodome.Util.number import long_to_bytes, bytes_to_long, getPrime

def ExtendedEuclid(a, b): # return x, y, gcd(a, b)
    if (b==0): return 1, 0, a
    x1, y1, d=ExtendedEuclid(b, a%b)
    x=y1 
    y=x1-y1*(a//b)
    return x, y, d

# Tính căn bậc e của x 
def integer_root(x, e):
    low, high = 0, x
    while low <= high:
        mid = (low + high) // 2
        mid_pow = mid ** e
        if mid_pow == x:
            return mid
        elif mid_pow < x:
            low = mid + 1
        else:
            high = mid - 1
    return high 

# input: pt(btyes), return n, e1, e2, ct1, ct2 
def encrypt(pt):
    m=bytes_to_long(pt)
    p=getPrime(1024)
    q=getPrime(1024)
    n=p*q 
    if (m>=n): 
        raise ValueError("LỖI: Plaintext quá lớn (lớn hơn n)")
    e1=getPrime(17)
    e2=getPrime(17)
    ct1=pow(m, e1, n)
    ct2=pow(m, e2, n)
    return n, e1, e2, ct1, ct2 

def attack(n, e1, e2, ct1, ct2): # return plaintext(bytes)
    a, b, gcd=ExtendedEuclid(e1, e2)
    m_gcd=(pow(ct1, a, n)*pow(ct2, b, n))%n 
    m=integer_root(m_gcd, gcd)
    return long_to_bytes(m)

def main(): 
    pt=input("Nhap plaintext: ").encode()
    n, e1, e2, ct1, ct2=encrypt(pt)
    recover=attack(n, e1, e2, ct1, ct2)
    _,  __, gcd=ExtendedEuclid(e1, e2)
    print(f"n: {n}")
    print(f"e1: {e1}")
    print(f"e2: {e2}")
    print(f"ct1: {ct1}")
    print(f"ct2: {ct2}")
    print(f"gcd(e1, e2): {gcd}")
    print(f"attack: {recover}")

if __name__=="__main__": 
    main()

