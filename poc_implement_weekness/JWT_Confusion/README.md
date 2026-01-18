# JWT Algorithm Confusion PoC

Đây là **Proof of Concept** minh họa lỗ hổng **Algorithm Confusion** (hay còn gọi là Key Confusion Attack) trong việc triển khai xác thực JWT (JSON Web Token).

Dự án này mô phỏng cách một Hacker có thể vượt qua cơ chế xác thực RSA (bất đối xứng) bằng cách ép Server sử dụng thuật toán HMAC (đối xứng) với Public Key đóng vai trò là mật khẩu (Secret Key).

---

## 🧠 Giới thiệu lỗ hổng

**Algorithm Confusion** xảy ra khi Server không kiểm tra chặt chẽ thuật toán ký (`alg`) trong Header của JWT mà tin tưởng tuyệt đối vào nó.

### Cơ chế hoạt động:

1. **Bình thường:** Server dùng **RS256**. Server dùng Private Key để ký và Public Key để verify.
2. **Tấn công:**
* Hacker lấy được Public Key của Server (thông tin này thường công khai).
* Hacker sửa Header của token thành `{"alg": "HS256"}`.
* Hacker ký token bằng thuật toán **HS256** (HMAC), sử dụng chuỗi bytes của **Public Key** làm **Secret Key**.


3. **Tại Server lỗi:**
* Server đọc Header thấy `HS256`.
* Server chuyển thư viện verify sang chế độ HMAC.
* Server truyền biến `public_key` vào hàm verify.
* **Kết quả:** Thư viện coi `public_key` là chuỗi mật khẩu HMAC  Khớp với chữ ký của Hacker  **Đăng nhập thành công với quyền Admin**.



---

## 📂 Cấu trúc dự án

* **`vuln_server.py`**: Server chứa lỗ hổng. Code xác thực tin tưởng header `alg` và truyền Public Key vào hàm decode mà không giới hạn thuật toán.
* **`secure_server.py`**: Server đã vá lỗi. Code xác thực ép buộc thuật toán phải là `RS256`, bất chấp header gửi lên là gì.
* **`attack.py`**: Script tấn công. Thực hiện giả mạo token bằng cách dùng Public Key làm HMAC Secret và gửi đến cả 2 server để kiểm chứng.

---

## 🛠 Yêu cầu cài đặt

Dự án sử dụng Python 3. Bạn cần cài đặt thư viện `pyjwt` và `pycryptodome`:

```bash
pip install pyjwt pycryptodome

```

---

## 🚀 Hướng dẫn chạy Demo

1. Đảm bảo bạn có đủ 3 file (`vuln_server.py`, `secure_server.py`, `attack.py`) trong cùng một thư mục.
2. Mở terminal tại thư mục đó và chạy lệnh:

```bash
python attack.py

```

---

## 🕵️ Phân tích kịch bản tấn công 

Kịch bản sẽ chạy qua 2 giai đoạn:

### Giai đoạn 1: Tấn công Vulnerable Server

* **Hacker:** Tạo token với Payload `{"role": "admin"}`, Header `alg="HS256"`. Ký bằng Public Key của Server.
* **Server:**
* Nhận token, đọc header thấy `HS256`.
* Dùng Public Key để verify theo chuẩn HMAC.
* Chữ ký khớp.


* **Kết quả:** In ra dòng chữ màu xanh lá: `>>> THÀNH CÔNG! Server Lỗi đã chấp nhận token giả.`

### Giai đoạn 2: Tấn công Secure Server

* **Hacker:** Gửi cùng loại token giả mạo đó lên Secure Server.
* **Server:**
* Hàm verify được cấu hình: `algorithms=["RS256"]`.
* Token gửi lên là `HS256`.
* Thư viện phát hiện sự không khớp (Mismatch).


* **Kết quả:** In ra dòng thông báo: `>>> BỊ CHẶN! Secure Server từ chối token.`

---

## 🛡 Giải pháp khắc phục

Để phòng chống lỗ hổng này, **KHÔNG BAO GIỜ** tin tưởng vào header của JWT để quyết định thuật toán verify.

**Vulnerable:**

```python
# Nguy hiểm: Cho phép mọi thuật toán client gửi lên
alg = jwt.get_unverified_header(token)['alg']
jwt.decode(token, key, algorithms=[alg])

```

**Code đúng:**

```python
# An toàn: Hardcode thuật toán mong muốn
jwt.decode(token, key, algorithms=["RS256"])

```

---

*Dự án phục vụ mục đích học tập và nghiên cứu an toàn thông tin.*