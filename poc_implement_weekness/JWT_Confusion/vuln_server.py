import jwt
from Crypto.PublicKey import RSA

class VulnerableJWTServer:
    def __init__(self):
        # 1. Tạo cặp khóa RSA 2048 bit bằng PyCryptodome
        self.key_pair = RSA.generate(2048)
        
        # Private Key (để ký) và Public Key (để verify)
        self.private_pem = self.key_pair.export_key()
        self.public_pem = self.key_pair.publickey().export_key()

    def login(self, username):
        """Tạo token hợp lệ cho user (Dùng RS256 chuẩn)"""
        payload = {"user": username, "role": "user"}
        token = jwt.encode(payload, self.private_pem, algorithm="RS256")
        return token

    def verify_request(self, token):
        try:
            # --- LỖI Ở ĐÂY ---
            # 1. Lấy thuật toán từ Header (chưa được verify)
            header = jwt.get_unverified_header(token)
            alg = header['alg']
            
            # 2. Dùng Public Key để verify, nhưng lại cho phép mọi thuật toán (alg)
            # Nếu alg='HS256', thư viện sẽ hiểu 'self.public_pem' là chuỗi MẬT KHẨU (HMAC Secret)
            # thay vì là RSA Key.
            if alg == 'HS256':
                # Sử dụng modulus làm HMAC secret
                pub_key = RSA.import_key(self.public_pem)
                secret = pub_key.n.to_bytes((pub_key.n.bit_length() + 7) // 8, 'big')
            else:
                secret = self.public_pem
            
            decoded = jwt.decode(token, secret, algorithms=[alg])
            
            return True, decoded
        except Exception as e:
            return False, str(e)

# Khởi tạo server
server = VulnerableJWTServer()
# Giả lập việc Public Key bị lộ (hoặc do server công khai)
exposed_public_key = server.public_pem