import jwt
from Crypto.PublicKey import RSA

class SecureJWTServer:
    def __init__(self):
        # Setup y hệt server lỗi
        self.key_pair = RSA.generate(2048)
        self.private_pem = self.key_pair.export_key()
        self.public_pem = self.key_pair.publickey().export_key()

    def login(self, username):
        payload = {"user": username, "role": "user"}
        token = jwt.encode(payload, self.private_pem, algorithm="RS256")
        return token

    def verify_request(self, token):
        try:
            # --- FIX Ở ĐÂY ---
            # Không quan tâm header gửi lên là gì.
            # Chỉ chấp nhận duy nhất thuật toán RS256.
            # Nếu hacker gửi HS256, thư viện sẽ báo lỗi "InvalidAlgorithmError" ngay.
            decoded = jwt.decode(token, self.public_pem, algorithms=["RS256"])
            
            return True, decoded
        except Exception as e:
            return False, str(e)

fixed_server = SecureJWTServer()