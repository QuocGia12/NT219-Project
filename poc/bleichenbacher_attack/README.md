# Proof of Concept: Bleichenbacher Attack on RSA PKCS#1 v1.5

## Mục tiêu
Triển khai tấn công Bleichenbacher (CCA attack) trên RSA với padding PKCS#1 v1.5, chứng minh khả năng khôi phục plaintext chỉ dựa vào oracle padding mà không cần private key.

## Tổng quan
Tấn công Bleichenbacher (còn gọi là "Million Message Attack") khai thác lỗ hổng trong cơ chế padding PKCS#1 v1.5 bằng cách sử dụng padding oracle để dần dần thu hẹp khoảng có thể của plaintext cho đến khi tìm được giá trị chính xác.

## Kiến trúc hệ thống

### 1. Oracle Server (`oracle_server.py`)
- Lắng nghe kết nối TCP trên port 9999.
- Sẽ cung cấp public key (n, e) khi client kết nối.
- Nhận ciphertext và trả về:
  - "1" nếu padding hợp lệ.
  - "0" nếu padding không hợp lệ.

### 2. Bleichenbacher Attacker (`bleichenbacher_attack.py`)
- Kết nối đến oracle server.
- Thực hiện toàn bộ quy trình tấn công:
  - Tạo ciphertext mẫu từ plaintext đã biết.
  - Tìm s1 ban đầu.
  - Thu hẹp khoảng tìm kiếm qua nhiều iteration.
  - Khôi phục plaintext.

## Thuật toán tấn công

### Các bước chính:

1. **Khởi tạo**
   - Kết nối đến oracle, nhận public key.
   - Tính tham số `B = 2^(8*(k-2))`.
   - Tạo ciphertext gốc `c0` từ plaintext mẫu.

2. **Tìm s1 đầu tiên**
   - Tìm s1 nhỏ nhất sao cho `c0 × s1^e mod n` có padding hợp lệ.
   - Bắt đầu từ `s1 = ceil(n / 3B)`.

3. **Thu hẹp khoảng**
   - Khởi tạo `M = {2B, 3B-1}`.
   - Với mỗi s tìm được, cập nhật tập khoảng M:
     ```
     M_{i+1} = ∪ [max(a, ceil((2B + rn)/s)), min(b, floor((3B-1 + rn)/s))]
     ```

4. **Tìm s tiếp theo**
   - Nếu `|M| > 1`: tìm s > s_prev.
   - Nếu `|M| = 1`: tìm s tối ưu trong khoảng xác định.

5. **Lặp cho đến khi tìm được plaintext**
   - Tiếp tục cho đến khi `|M| = 1` và `a = b`.
   - Khi đó, `a` chính là plaintext cần tìm.

## Kết quả thực nghiệm

Với RSA key 256-bit và plain text thử nghiệm `byebye`:
- Thành công hoàn toàn: Tìm được plaintext chính xác.
- Thời gian: 39.91 giây.
- Số iteration: 216 vòng lặp.
- Số query: 315670 query để tìm s0 ban đầu.

Với RSA key 256-bit và plain text thử nghiệm `hello world`:
- Thành công hoàn toàn: Tìm được plaintext chính xác.
- Thời gian: 149.50 giây.
- Số iteration: 221 vòng lặp.
- Số query: 1090963 query để tìm s0 ban đầu.

=> Plain text có độ dài càng lớn thì thời gian khôi phục càng lâu.
## Ứng dụng thực tế
Tấn công này vẫn cực kỳ nguy hiểm vì trong thực tế, các thông tin quan trọng nhất thường rất ngắn: session keys, encryption keys, passwords. Chỉ cần decrypt thành công 16-32 bytes là có thể lấy được AES key để decrypt GBs dữ liệu, hoặc master password để truy cập toàn bộ hệ thống.

Kịch bản tấn công thường gặp: TLS handshake, password vaults, API authentication - nơi RSA được dùng để mã hóa các secrets ngắn nhưng then chốt.

## Kết luận

PoC chứng minh thành công:
- RSA PKCS#1 v1.5 dễ bị tấn công padding oracle.
- Bleichenbacher attack có thể khôi phục plaintext hoàn toàn.
- Cần chuyển sang OAEP padding để bảo mật tốt hơn.

## Biện pháp phòng thủ
- Sử dụng RSA-OAEP thay cho PKCS#1 v1.5.
- Không trả về thông tin chi tiết về lỗi padding.
- Sử dụng constant-time comparison trong kiểm tra padding.