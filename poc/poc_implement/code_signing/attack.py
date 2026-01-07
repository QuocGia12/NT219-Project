from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from vuln_server import VulnerableRSAServer
from fixed_server import SecureRSAServer

# --- CẤU HÌNH ---
print("Hãy chọn server để test:")
print("1. Vulnerable Server (LỖI)")
print("2. Secure Server (AN TOÀN)")
while True:
    choice = input("Nhập 1 hoặc 2: ")
    if choice == '1':
        USE_SECURE = False
        break
    elif choice == '2':
        USE_SECURE = True
        break
    else:
        print("Lựa chọn không hợp lệ. Vui lòng nhập lại.")

# 1. Setup RSA Keys (2048 bits)
key_pair = RSA.generate(2048)
n = key_pair.n
d = key_pair.d
print("-----------------------------------")
if USE_SECURE:
    print(">>> MODE: SECURE SERVER")
    server = SecureRSAServer(key_pair)
else:
    print(">>> MODE: VULNERABLE SERVER (LỖI)")
    server = VulnerableRSAServer(key_pair)
print("-----------------------------------")

# Message và Nonce
message = "Transfer 500 USD for Tommy"
nonce = 101
msg_to_sign = f"{message}||{nonce}"

# 2. Tạo chữ ký gốc (Sig1) - Tính toán Raw RSA
print("\n--- BƯỚC 1: User ký và gửi (Sig1) ---")
# Hash message
h_obj = SHA256.new(msg_to_sign.encode('utf-8'))
h_int = int.from_bytes(h_obj.digest(), byteorder='big')

# Ký: s = h^d mod n
s_int = pow(h_int, d, n)

# Chuyển thành bytes (Độ dài chuẩn: 256 bytes cho RSA-2048)
sig1_bytes = s_int.to_bytes(256, byteorder='big')

# Gửi lần 1
server.handle_request(message, nonce, sig1_bytes)


# 3. Tấn công Replay thông thường
print("\n--- BƯỚC 2: Hacker Replay Sig1 (Y hệt) ---")
# Vuln Server: Chặn (vì Sig1 trùng trong DB)
# Secure Server: Chặn (vì Nonce 101 trùng trong DB)
server.handle_request(message, nonce, sig1_bytes)


# 4. Tấn công Malleability (Thêm số 0 vào đầu)
print("\n--- BƯỚC 3: Hacker thêm Leading Zero (Sig2) ---")
# Hacker không có Key. Hắn lấy Sig1 và thêm 1 byte \x00 vào trước.
# Toán học: 0x00...123 == 0x...123 (Vẫn verify đúng!)
# Byte check: Sig2 != Sig1
sig2_bytes = b'\x00' + sig1_bytes

print(f"Sig1 Length: {len(sig1_bytes)}")
print(f"Sig2 Length: {len(sig2_bytes)} (Dài hơn 1 byte)")

# Vuln Server: BỊ LỪA (Vì sig2 bytes chưa có trong DB)
# Secure Server: CHẶN (Vì vẫn check Nonce 101)
server.handle_request(message, nonce, sig2_bytes)


# 5. Hacker đổi Nonce + Sig2 (Thử lừa Secure Server)
print("\n--- BƯỚC 4: Hacker đổi Nonce (102) + Sig2 ---")
# Secure Server check Nonce 102 (OK), nhưng Verify Toán học sẽ sai 
# vì Sig2 là chữ ký của Nonce 101, không phải 102.
server.handle_request(message, 102, sig2_bytes)