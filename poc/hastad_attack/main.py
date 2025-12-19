from Cryptodome.Util.number import bytes_to_long, long_to_bytes, inverse, getPrime

def CRT(a_list, m_list): 
    M=1
    for i in m_list: 
        M*=i
    res=0
    for ai, mi in zip(a_list, m_list): 
        Mi=M//mi
        ni=inverse(Mi, mi)
        res+=ai*Mi*ni
        res%=M
    return res

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



# input: pt(bytes); return n1, n2, n3, ct1, ct2, ct3
def encrypt(pt):
    p1=getPrime(1024)
    p2=getPrime(1024)
    p3=getPrime(1024)
    q1=getPrime(1024)
    q2=getPrime(1024)
    q3=getPrime(1024)

    n1=p1*q1
    n2=p2*q2
    n3=p3*q3 
    if m >= min(n1, n2, n3): 
        raise ValueError("LỖI: Plaintext quá lớn (lớn hơn n)")
    e=3

    m=bytes_to_long(pt)

    ct1=pow(m, e, n1)
    ct2=pow(m, e, n2)
    ct3=pow(m, e, n3)

    return n1, n2, n3, ct1, ct2, ct3 

def HastadAttack(n1, n2, n3, ct1, ct2, ct3): # return plaintext(bytes)
    n=[n1, n2, n3]
    ct=[ct1, ct2, ct3]

    m3=CRT(ct, n)
    N=n1*n2*n3
    m=integer_root(m3, 3)
    return long_to_bytes(m)

def main(): 
    pt=input("Nhập vào plaintext: ").encode()
    n1, n2, n3, ct1, ct2, ct3=encrypt(pt)
    recover = HastadAttack(n1, n2, n3, ct1, ct2, ct3)
    print(f"n1: {n1}")
    print(f"ct1: {ct1}")
    print(f"n2: {n2}")
    print(f"ct2: {ct2}")
    print(f"n3: {n3}")
    print(f"ct3: {ct3}")
    
    print(f"Recover: {recover}")

if __name__=="__main__": 
    main()



