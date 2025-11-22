# RSA Timing-based Padding Oracle Attack (Marvin Simulation)

Đây là Proof-of-Concept (PoC) minh họa cách khai thác lỗ hổng **Side-Channel** trên RSA. Thay vì dựa vào thông báo lỗi cụ thể (như tấn công Bleichenbacher truyền thống), công cụ này đo **thời gian phản hồi** của server để xác định tính hợp lệ của bản mã.

## 1. Cơ chế hoạt động

Tấn công này hoạt động như một "chiếc cầu nối" chuyển đổi tín hiệu **Thời gian** thành tín hiệu **Boolean** (True/False) để phục vụ thuật toán Bleichenbacher:

1.  **Calibration (Đo chuẩn):**

      * Gửi request có **Padding Đúng**: Server thực hiện tính toán (mô phỏng việc sinh session key) $\rightarrow$ Phản hồi **CHẬM**.
      * Gửi request có **Padding Sai**: Server phát hiện lỗi và dừng sớm $\rightarrow$ Phản hồi **NHANH**.
      * **Threshold (Ngưỡng):** Tính trung bình cộng giữa Chậm và Nhanh.

2.  **The Oracle:**

      * Khi thuật toán Bleichenbacher gửi một bản mã $c'$ bất kỳ:
      * Client đo thời gian phản hồi $T$.
      * Nếu $T > Threshold \rightarrow$ Oracle trả về **True** (Padding Valid).
      * Nếu $T < Threshold \rightarrow$ Oracle trả về **False** (Padding Invalid).

3.  **Key Recovery:**

      * Sử dụng tín hiệu True/False này để thu hẹp khoảng giá trị (Interval Narrowing) và tìm ra $m$ (PreMasterSecret).

## 2. Cấu trúc Code

Module được tách biệt để dễ quản lý:

  * `exploit.py`: Script chính. Điều phối quá trình tấn công và ghi log kết quả.
  * `oracle.py`: **"Bộ cảm biến"**. Chịu trách nhiệm kết nối mạng, đo `perf_counter`, lọc nhiễu và so sánh với Threshold.
  * `algorithm.py`: Logic toán học thuần túy của Bleichenbacher '98.
  * `config.py`: Cấu hình IP, Port, và số lượng mẫu đo (Samples) để khử nhiễu mạng.

## 3. Hướng dẫn chạy

### Bước 1: Dựng Server mục tiêu

Đảm bảo Server giả lập đang chạy (xem hướng dẫn tại folder `docker/`):

```bash
# Tại folder docker/
docker run --rm -it -p 9999:9999 openssl-marvin-lab
```

### Bước 2: Chạy tấn công

Tại thư mục `poc/marvin_attack/`:

```bash
python3 exploit.py
```

### Bước 3: Kiểm tra kết quả

Sau khi chạy xong, kết quả sẽ được lưu tự động vào thư mục `logs/marvin-attack`:

  * `attack_summary_*.txt`: Báo cáo tổng quan (Thời gian chạy, số queries, secret tìm được).
  * `timing_dist_*.csv`: Dữ liệu thô về thời gian phản hồi (dùng để vẽ biểu đồ chứng minh sự chênh lệch thời gian).