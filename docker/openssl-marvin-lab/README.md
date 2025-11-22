# Vulnerable RSA Timing Oracle Server (Marvin Simulation)

Server này là môi trường giả lập (Target) cho kịch bản tấn công **RSA Timing-based Padding Oracle**.

Nó mô phỏng một hệ thống TLS 1.2 thực hiện giải mã RSA và bị lộ thông tin qua Timing Side-channel, thay vì thông báo lỗi trực tiếp.

## 1. Cơ chế lỗ hổng

Server sử dụng thư viện **OpenSSL 1.1.1q** để giải mã, kết hợp với logic Python để giả lập độ trễ xử lý:

1.  **Decryption:** Server nhận ciphertext và giải mã bằng private key.
2.  **Padding Check:**
      * **Trường hợp Padding Đúng (Valid):** Server tiếp tục thực hiện quy trình tính toán khóa phiên giả lập (Derive Session Key). Quy trình này sử dụng các phép toán lũy thừa số lớn `pow(base, exp, mod)` với 4096 bits, gây tiêu tốn CPU đáng kể.
      * **Trường hợp Padding Sai (Invalid):** Server phát hiện lỗi padding và dừng xử lý sớm, bỏ qua bước tính toán nặng.
3.  **Response:** Trong cả 2 trường hợp, server đều trả về `OK`. Kẻ tấn công chỉ có thể phân biệt dựa trên thời gian phản hồi.

## 2. Cấu trúc Project

  * `Dockerfile`: Cài đặt Ubuntu 20.04, biên dịch OpenSSL 1.1.1q từ source, và tạo RSA Key 1024-bit.
  * `server_oracle.py`: Script Python đóng vai trò Oracle, xử lý kết nối TCP và giả lập độ trễ CPU.

## 3. Hướng dẫn Cài đặt & Chạy Server (Setup)

### Bước 1: Build Docker Image

Tại thư mục chứa `Dockerfile`, chạy lệnh:

```bash
docker build -t openssl-marvin-lab .
```

### Bước 2: Chạy Server

```bash
docker run --rm -it -p 9999:9999 openssl-marvin-lab
```

Sau khi khởi động, server sẽ báo `[+] Server Ready` kèm một số thông tin công khai (Public Modulus, Public Exponent,...).

## 4. Tuning

Trong file `server_oracle.py`, biến quan trọng nhất là `WORKLOAD_LOOPS`:

```python
WORKLOAD_LOOPS = 1  # Mặc định
```

  * **Ý nghĩa:** Quyết định số lượng phép tính BigNum server thực hiện khi padding đúng. Biến càng lớn thì thời gian respones cho Client càng lâu.

## 5. Giao thức giao tiếp

Client kết nối tới `TCP Port 9999` và tuân theo giao thức sau:

### 5.1. Handshake

Ngay khi kết nối, server gửi 3 thông tin:

```text
MODULUS:<hex_string>
EXPONENT:<hex_string>
CIPHERTEXT:<hex_string>
```

### 5.2. Query (Client gửi)

Để kiểm tra một bản mã $c'$:

1.  Client gửi: `<hex_string_c_prime>\n`
2.  Server phản hồi: `OK\n`

Client đo thời gian từ lúc gửi đến lúc nhận "OK".

  * **Thời gian dài:** Khả năng cao là Padding Đúng.
  * **Thời gian ngắn:** Khả năng cao là Padding Sai.

## 6. Một số thông số kỹ thuật

  * **OS:** Ubuntu 20.04 LTS.
  * **OpenSSL:** 1.1.1q. 
  * **Key Size:** RSA 1024 bits.
  * **BigNum Simulation:** 4096-bit Arithmetic Operations.

-----