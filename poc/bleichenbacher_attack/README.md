# Proof of Concept: Bleichenbacher Attack on RSA PKCS#1 v1.5

## Mục tiêu
Triển khai tấn công Bleichenbacher (Adaptive Chosen Ciphertext Attack) trên RSA với padding PKCS#1 v1.5, chứng minh khả năng khôi phục session secret chỉ dựa vào padding oracle mà không cần private key.

## Tổng quan
Tấn công Bleichenbacher (còn gọi là "Million Message Attack") khai thác lỗ hổng trong cơ chế padding PKCS#1 v1.5 bằng cách sử dụng padding oracle để dần dần thu hẹp khoảng có thể của plaintext cho đến khi tìm được giá trị chính xác.

## Kiến trúc hệ thống

### 1. Oracle Server (oracle_server.py)
- Port: 9999.
- Đặc điểm: Sử dụng PKCS#1 v1.5 padding - VULNERABLE.
- Chức năng:
  - Cung cấp RSA public key (n, e) khi client kết nối.
  - Thực hiện handshake protocol với session secret.
  - Trả về padding oracle: "1" nếu padding hợp lệ, "0" nếu không hợp lệ.
  - Sinh session secret 16-byte ngẫu nhiên cho mỗi kết nối.

### 2. Secure Server (secure_server.py)
- Port: 9990.
- Đặc điểm: Sử dụng RSA-OAEP padding - PROTECTED.
- Chức năng:
  - Chỉ chấp nhận RSA-OAEP, từ chối PKCS#1 v1.5.
  - Constant-time operations để ngăn timing attacks.
  - HMAC protection cho tất cả messages.
  - Giới hạn số lượng oracle queries.

### 3. Session Attacker (session_attack.py)
- Chức năng: Tấn công cả hai server để so sánh.
- Tính năng:
  - Tự động phát hiện server type.
  - Thực hiện Bleichenbacher attack hoàn chỉnh.
  - Đo lường thời gian và hiệu quả tấn công.

## Protocol Handshake

### Client-Server Handshake:
1. Server → Client: Gửi session ID, modulus (n), exponent (e).
2. Client → Server: Gửi ClientHello encrypted với PKCS#1 v1.5.
3. Server → Client:
   - Oracle Server: Gửi session secret encrypted với PKCS#1 v1.5.
   - Secure Server: Từ chối nếu dùng PKCS#1 v1.5.

## Thuật toán Bleichenbacher Attack

### Các bước chính:

1. Khởi tạo.
   - Kết nối đến server, nhận public key và encrypted session secret.
   - Tính tham số: B = 2^(8*(k-2)) với k là kích thước modulus.
   - Khởi tạo tập khoảng: M = {[2B, 3B-1]}.

2. Tìm s₀ ban đầu.
   ```python
   s = ceil(n / 3B)
   while True:
       c' = (c₀ × s^e) mod n
       if oracle(c') == 1:
           return s
       s += 1
   ```

3. Thu hẹp khoảng với s.
   - Với mỗi khoảng [a,b] trong M:
     ```python
     r_min = ceil(a × s - 3B + 1, n)
     r_max = floor(b × s - 2B, n)
     for r in range(r_min, r_max + 1):
         low = max(a, ceil(2B + r × n, s))
         high = min(b, floor(3B - 1 + r × n, s))
     ```

4. Tìm s tiếp theo.
   - Nếu |M| > 1: tìm s > s_prev.
   - Nếu |M| = 1: tìm s tối ưu trong khoảng xác định.

5. Khôi phục plaintext.
   - Khi |M| = 1 và a = b: extract plaintext từ PKCS#1 padding.

## Kết quả thực nghiệm

### Tấn công Oracle Server (9999):
- Thành công: Có thể khôi phục session secret 16-byte.
- Thời gian: 30-180 giây tùy vào điều kiện mạng.
- Số queries: 50,000 - 1,000,000 queries.
- Kết luận: PKCS#1 v1.5 hoàn toàn không an toàn.

### Tấn công Secure Server (9990):
- Kết quả: Thất bại hoàn toàn.
- Lý do:
  - RSA-OAEP không bị ảnh hưởng bởi padding oracle.
  - Constant-time operations ngăn timing attacks.
  - HMAC protection chống message tampering.

## Cách chạy PoC

### 1. Khởi động servers:
```bash
# Terminal 1 - Oracle Server (Vulnerable)
python3 oracle_server.py

# Terminal 2 - Secure Server (Protected)
python3 secure_server.py
```

### 2. Chạy tấn công:
```bash
python3 session_attack.py
```

### 3. Chọn server để tấn công:
```
SELECT SERVER TO ATTACK
==================================================
1 - Oracle Server (Port 9999) - VULNERABLE
    • Uses PKCS#1 v1.5
    • Vulnerable to Bleichenbacher
2 - Secure Server (Port 9990) - PROTECTED
    • Uses RSA-OAEP
    • Constant-time + Error hiding
```

## Biện pháp phòng thủ đã triển khai

### Trong Secure Server:
1. RSA-OAEP Padding: Thay thế PKCS#1 v1.5.
2. Constant-time Operations: Luôn trả về sau 10ms.
3. HMAC Protection: Tất cả messages được xác thực.ion.
4. Error Hiding: Không tiết lộ chi tiết lỗi.

## Bài học quan trọng

1. PKCS#1 v1.5 nguy hiểm: Không bao giờ sử dụng cho mã hóa RSA mới.
2. Oracle responses leak information: Mọi thông tin về validity đều có thể bị khai thác.
3. Security through obscurity doesn't work: Che giấu error details là không đủ.
4. Use RSA-OAEP: Luôn sử dụng OAEP padding cho mã hóa RSA.

## Ứng dụng thực tế

Tấn công này cực kỳ nguy hiểm vì:
- Targets short secrets: Session keys, encryption keys (16-32 bytes).
- Practical scenarios: TLS handshake, API authentication, password vaults.
- High impact: Chỉ cần decrypt 16 bytes có thể lấy được AES key để decrypt GBs dữ liệu.

## Kết luận

PoC chứng minh thành công:
- Bleichenbacher attack hoạt động hiệu quả trên PKCS#1 v1.5.
- RSA-OAEP + proper protections ngăn chặn hoàn toàn tấn công.
- Importance of constant-time operations và proper error handling.

Khuyến nghị: Luôn sử dụng RSA-OAEP cho mã hóa RSA và triển khai proper protections chống side-channel attacks.