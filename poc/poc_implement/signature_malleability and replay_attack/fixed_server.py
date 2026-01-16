from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

class SecureRSAServer:
    def __init__(self, key_pair):
        self.public_key = key_pair.publickey()
        # FIX: Dùng Nonce làm ID (Best Practice)
        self.used_nonces = set()

    def manual_verify(self, content, signature_bytes):
        # (Giống hệt hàm bên Vuln Server - Toán học không đổi)
        try:
            s_int = int.from_bytes(signature_bytes, byteorder='big')
            h = SHA256.new(content.encode('utf-8'))
            h_int = int.from_bytes(h.digest(), byteorder='big')
            hash_from_sig = pow(s_int, self.public_key.e, self.public_key.n)
            return hash_from_sig == h_int
        except Exception:
            return False

    def handle_request(self, message, nonce, signature_bytes):
        full_content = f"{message}||{nonce}"
        
        print(f"\n[SECURE-SERVER] Req: '{message}' | Nonce: {nonce}")

        # --- FIX: CHECK REPLAY BẰNG NONCE ---
        # Bất chấp chữ ký có biến hình thế nào, Nonce vẫn là cũ -> Chặn.
        if nonce in self.used_nonces:
            print(f"❌ [BLOCK] Replay Attack! Nonce {nonce} đã được sử dụng.")
            return False

        # Verify Toán học
        if self.manual_verify(full_content, signature_bytes):
            # Kiểm tra thêm độ dài chuẩn tắc (Optional Defense)
            expected_len = self.public_key.n.bit_length() // 8
            if len(signature_bytes) > expected_len:
                print("⚠️ [WARN] Chữ ký Valid nhưng sai Format (Non-canonical). Vẫn chấp nhận vì Nonce mới.")
            else:
                print("✅ [SUCCESS] Verify Success -> Thực thi lệnh!")
            
            # Đánh dấu Nonce đã dùng
            self.used_nonces.add(nonce)
            return True
        else:
            print("❌ [FAIL] RSA Verify Failed.")
            return False