from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

class VulnerableRSAServer:
    def __init__(self, key_pair):
        self.public_key = key_pair.publickey()
        # LỖI: Dùng Signature Bytes làm ID để chống Replay
        self.used_signatures = set()

    def manual_verify(self, content, signature_bytes):
        """
        Verify RSA thủ công (Raw RSA) để thấy rõ bản chất toán học.
        S^e mod n == Hash(Content)
        """
        try:
            # 1. Convert Bytes -> Int (Số 0 ở đầu sẽ bị mất tại đây -> Cội nguồn vấn đề)
            s_int = int.from_bytes(signature_bytes, byteorder='big')
            
            # 2. Tính Hash message
            h = SHA256.new(content.encode('utf-8'))
            h_int = int.from_bytes(h.digest(), byteorder='big')
            
            # 3. Tính toán RSA: hash = s^e mod n
            hash_from_sig = pow(s_int, self.public_key.e, self.public_key.n)
            
            return hash_from_sig == h_int
        except Exception:
            return False

    def handle_request(self, message, nonce, signature_bytes):
        # Ghép nội dung để verify (Message + Nonce)
        full_content = f"{message}||{nonce}"
        
        # Tạo ID để check DB: Dùng toàn bộ chuỗi bytes của chữ ký
        # Nếu hacker thêm \x00 vào đầu, chuỗi bytes này sẽ khác đi.
        sig_id = signature_bytes.hex()

        print(f"\n[VULN-SERVER] Req: '{message}' | Nonce: {nonce}")
        print(f"              Sig Len: {len(signature_bytes)} bytes")

        # --- LỖI LOGIC CHECK REPLAY ---
        if sig_id in self.used_signatures:
            print("❌ [FAIL] Replay Attack Detected (Signature đã dùng).")
            return False

        # Verify Toán học
        if self.manual_verify(full_content, signature_bytes):
            print("✅ [OK] RSA Verify Success -> Thực thi lệnh!")
            self.used_signatures.add(sig_id)
            return True
        else:
            print("❌ [FAIL] RSA Verify Failed.")
            return False