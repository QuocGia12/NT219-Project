from flask import Flask, request, jsonify
import jwt, time, base64
from weak_rsa import generate_weak_rsa

app = Flask(__name__)

n, e, d = generate_weak_rsa()

def b64(x):
    return base64.urlsafe_b64encode(
        x.to_bytes((x.bit_length()+7)//8, "big")
    ).decode().rstrip("=")

PRIVATE_KEY = {"n": n, "e": e, "d": d}

PUBLIC_JWK = {
    "kty": "RSA",
    "kid": "weak-key",
    "alg": "RS256",
    "use": "sig",
    "n": b64(n),
    "e": b64(e)
}

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    if data["username"] == "user" and data["password"] == "password":
        payload = {
            "sub": "user",
            "role": ["USER"],
            "iss": "auth-service",
            "aud": "api-gateway",
            "exp": int(time.time()) + 300
        }

        token = jwt.encode(
            payload,
            PRIVATE_KEY,
            algorithm="RS256",
            headers={"kid": "weak-key"}
        )
        return jsonify({"access_token": token})

    return "Unauthorized", 401

@app.route("/.well-known/jwks.json")
def jwks():
    return jsonify({"keys": [PUBLIC_JWK]})

app.run(host="0.0.0.0", port=8000)
