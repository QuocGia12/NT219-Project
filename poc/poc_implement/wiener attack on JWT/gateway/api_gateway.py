from flask import Flask, request, jsonify
import jwt
import requests
import time
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ================= CONFIG =================

JWKS_URL = "http://auth:8000/.well-known/jwks.json"
ISSUER = "auth-service"
AUDIENCE = "api-gateway"
RETRY_MAX = 10

app = Flask(__name__)

public_key = None

# ================= UTILS =================

def b64url_to_int(val: str) -> int:
    padding = '=' * (-len(val) % 4)
    return int.from_bytes(
        base64.urlsafe_b64decode(val + padding),
        byteorder="big"
    )

def load_rsa_public_key_from_jwks(jwks: dict):
    key = jwks["keys"][0]

    n = b64url_to_int(key["n"])
    e = b64url_to_int(key["e"])

    pub = rsa.RSAPublicNumbers(e, n).public_key()
    return pub

def fetch_jwks_with_retry():
    global public_key

    for i in range(RETRY_MAX):
        try:
            print("[gateway] Fetching JWKS...")
            r = requests.get(JWKS_URL, timeout=2)
            r.raise_for_status()
            jwks = r.json()

            public_key = load_rsa_public_key_from_jwks(jwks)
            print("[gateway] RSA public key loaded")
            return

        except Exception as e:
            print(f"[gateway] JWKS not ready ({i+1}/{RETRY_MAX}): {e}")
            time.sleep(1)

    raise RuntimeError("JWKS unavailable")

# ================= INIT =================

fetch_jwks_with_retry()

# ================= MIDDLEWARE =================

def verify_jwt(token: str):
    payload = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER
    )
    return payload

# ================= ROUTES =================

@app.route("/api/admin")
def admin_api():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "missing token"}), 401

    token = auth.split()[1]

    try:
        claims = verify_jwt(token)
    except Exception as e:
        return jsonify({"error": "invalid token", "detail": str(e)}), 403

    # ===== RBAC CHECK =====
    if "admin" not in claims.get("role", []):
        return jsonify({"error": "forbidden"}), 403


    return jsonify({
        "message": "FULL SYSTEM ACCESS GRANTED",
        "user": claims.get("sub"),
        "claims": claims
    })

@app.route("/health")
def health():
    return "ok"

# ================= MAIN =================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
