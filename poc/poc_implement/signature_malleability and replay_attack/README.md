# RSA Signature Malleability & Replay Attack PoC

Đây là **Proof of Concept (PoC)** minh họa lỗ hổng **Signature Malleability** (Tính dễ uốn của chữ ký) trong việc triển khai thuật toán RSA và cách nó dẫn đến lỗ hổng nghiêm trọng **Replay Attack**.

Dự án này được xây dựng để demo sự khác biệt giữa việc xử lý sai (dựa vào chữ ký để định danh) và xử lý đúng (dựa vào Nonce).

## 🛠 Yêu cầu hệ thống

Dự án được viết bằng **Python 3**.
Thư viện duy nhất cần cài đặt là `pycryptodome`.

```bash
pip install pycryptodome
```

## 📂 Cấu trúc dự án

Dự án bao gồm 3 file chính:

1. **`vuln_server.py`:**
* Mô phỏng server bị lỗi logic.
* Sử dụng **chuỗi Bytes của chữ ký** làm ID để kiểm tra trùng lặp (Blacklist).
* Thực hiện xác thực RSA thuần (Raw RSA) mà không kiểm tra định dạng chuẩn tắc (Canonical format).


2. **`fixed_server.py`:**
* Mô phỏng server bảo mật.
* Sử dụng **Nonce** (Number used once) đi kèm trong message để định danh giao dịch.
* Bỏ qua việc chữ ký trông như thế nào, chỉ quan tâm ID giao dịch (Nonce) đã được sử dụng hay chưa.


3. **`attack.py`:**
* Đóng vai trò là User (ký hợp lệ) và Hacker (tạo chữ ký biến hình để tấn công).

## 🧠 Cơ sở lý thuyết & Lỗ hổng

### 1. RSA Signature Malleability (Biến thể Leading Zeros)

Trong RSA, chữ ký thực chất là một số nguyên lớn . Khi truyền tải, số nguyên này được chuyển đổi thành chuỗi Bytes.

* Về mặt toán học: Số `123` và số `00123` là **bằng nhau**.
* Về mặt dữ liệu (Bytes): Chuỗi `\x7b` và `\x00\x00\x7b` là **khác nhau**.

Hàm `int.from_bytes()` trong Python (và nhiều thư viện khác) sẽ tự động loại bỏ các số 0 ở đầu khi tính toán xác thực RSA. Điều này tạo ra một sự không nhất quán.

### 2. Kịch bản tấn công

Nếu Server lưu trữ **chữ ký gốc** (dạng bytes) vào Database để chặn việc gửi lại (Replay Protection):

1. Hacker bắt được chữ ký hợp lệ `Sig1`.
2. Hacker thêm byte `0x00` vào đầu để tạo thành `Sig2`.
3. Hacker gửi `Sig2` lên Server.
* **Database check:** `Sig2` khác `Sig1`  Cho qua (Tưởng là request mới).
* **RSA Verify:** `int(Sig2)` == `int(Sig1)`  Chữ ký đúng toán học  **Thực thi lệnh lần 2**.



---

## 🚀 Hướng dẫn chạy Demo

Mở terminal tại thư mục dự án và chạy lệnh:

```bash
python attack.py
```

## 🕵️ Phân tích kịch bản tấn công

Quy trình chạy qua 4 bước:

### Bước 1: User gửi giao dịch gốc (Sig1)

* User tạo chữ ký chuẩn `Sig1` (256 bytes) cho message kèm Nonce `101`.
* **Kết quả:** Cả 2 server đều chấp nhận và thực thi.

### Bước 2: Tấn công Replay thông thường

* Hacker gửi lại y nguyên `Sig1` và `Nonce 101`.
* **Kết quả:** Bị chặn bởi cả 2 server (Do trùng lặp).

### Bước 3: Tấn công Malleability

* Hacker tạo `Sig2` bằng cách thêm byte `\x00` vào trước `Sig1`.
* **Tại Vulnerable Server:**
* Check DB: `Sig2` (257 bytes) chưa có trong kho lưu trữ  Pass.
* Verify RSA: `int(Sig2)` vẫn đúng với Public Key  Pass.
* **Hậu quả:** Giao dịch được thực hiện lần 2 (Mất tiền).


* **Tại Secure Server:**
* Check DB: Server kiểm tra `Nonce 101`. Thấy Nonce này đã dùng rồi.
* **Kết quả:** Chặn đứng tấn công (`❌ [BLOCK] Replay Attack`).



### Bước 4: Hacker đổi Nonce + Sig2

* Hacker thử đổi `Nonce` sang `102` để lừa bộ lọc trùng lặp của Secure Server, nhưng vẫn dùng chữ ký `Sig2` (được ký cho 101).
* **Kết quả:**
* Check DB: Pass (vì Nonce 102 mới).
* Verify RSA: Fail (Vì chữ ký không khớp với nội dung `Message + 102`).  **An toàn**.
