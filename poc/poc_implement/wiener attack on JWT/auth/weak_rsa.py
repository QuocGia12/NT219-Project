from Crypto.Util.number import getPrime, inverse

def generate_weak_rsa(bits=2048):
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)

        d = getPrime(128)  # CỐ Ý NHỎ (Wiener vulnerable)
        try:
            e = inverse(d, phi)
            if e < phi:
                return n, e, d
        except:
            continue
