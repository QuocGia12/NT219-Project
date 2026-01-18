# Cryptanalysis on Asymmetric Ciphers: RSA & RSA‑Based Signatures

**Môn học:** NT219 - Cryptography\
**Lớp:** NT219.Q11.ANTN\
**Giảng viên:** Thầy Nguyễn Ngọc Tự

**Thông tin nhóm:**
| STT. | Tên | MSSV |
|:-------:|-------|:-------:|
| 1 | Nguyễn Thị Mỹ Duyên | 24520408 |
| 2 | Nguyễn Văn Quốc Gia | 24520415 |

---
## Giới thiệu 
- Hiện nay, RSA vẫn là một trong những thuật toán khóa công khai được sử dụng rộng rãi nhất, đặc biệt trong các giao thức TLS/SSL, trao đổi khóa và chữ ký số. Nền tảng an toàn của mã hóa RSA dựa trên độ khó tính toán của bài toán phân tích các số nguyên lớn thành các thừa số nguyên tố của chúng. Đối với máy tính cổ điển, thuật toán hiệu quả nhất hiện nay được biết đến cho bài toán này là General Number Field Sieve (GNFS).
- Tuy nhiên, thuật toán này vẫn không khả thi đối với các khóa có độ dài 2048 bit hoặc lớn hơn. Do đó, nếu được triển khai đúng cách, RSA vẫn được xem là an toàn ở thời điểm hiện tại. Mặc dù vậy, các mối đe dọa đối với RSA đang **gia tăng**. Một số vấn đề phát sinh từ các lỗi trong quá trình **triển khai** hoặc từ các **bộ sinh số ngẫu nhiên yếu**, dẫn đến việc nhiều khóa RSA bị xâm phạm do dùng chung các thừa số nguyên tố. Ngoài ra, các tấn công kênh kề (**side-channel attacks**) như phân tích thời gian, phân tích mức tiêu thụ điện năng và phân tích bức xạ điện từ có thể làm rò rỉ khóa bí mật trong các môi trường phần cứng.
- Hơn nữa, sự xuất hiện của **máy tính lượng tử** đặt ra một mối đe dọa lớn đối với RSA. **Thuật toán Shor** cho thấy rằng nếu tồn tại một máy tính lượng tử đủ lớn và ổn định, việc phân tích các số nguyên lớn — và do đó phá vỡ RSA — có thể được thực hiện trong một khoảng thời gian khả thi trên thực tế.

Do đó, việc hiểu rõ **các khái niệm nền tảng** và **các lý thuyết đằng sau các tấn công lên RSA** giúp các tổ chức đánh giá rủi ro và thận trọng hơn khi triển khai RSA trong các dự án của mình.

## Cấu trúc Kho lưu trữ

### 1. `docker/`

Cấu hình Docker để tạo môi trường phòng thí nghiệm (lab) biệt lập, dùng để mô phỏng và kiểm thử các cuộc tấn công RSA:

* **`common-modulus-attack/`**: Môi trường thử nghiệm tấn công hệ thống dùng chung modulus nhưng khác số mũ công khai (public exponent).
* **`hastad-attack/`**: Thiết lập tấn công quảng bá (broadcast attack) trên mã hóa RSA số mũ nhỏ.
* **`openssl-marvin-lab/`**: Lab minh họa tấn công Marvin (timing-based padding oracle).
* **`wiener-lab/`**: Môi trường cho tấn công Wiener nhắm vào số mũ bí mật (private exponent) nhỏ.

### 2. `docs/`:
Chứa báo cáo môn học hoàn chỉnh.

### 3. `logs/`

Chứa kết quả thực nghiệm và dữ liệu thu được từ các mô phỏng tấn công.

### 4. `poc/`

Mã nguồn Bằng chứng khái niệm (Proof-of-Concept) cho các tấn công cốt lõi:

* **`bleichenbacher_attack/`**: Tấn công PKCS#1 v1.5 padding oracle.
* **`common_modulus_attack/`**: Tấn công kịch bản chia sẻ modulus.
* **`hastad_attack/`**: Tấn công quảng bá số mũ nhỏ.
* **`marvin_attack/`**: Tấn công padding oracle dựa trên thời gian.
* **`RSA_CRT_fault_attack/`**: Tấn công tiêm lỗi trên RSA-CRT.
* **`wiener_attack/`**: Tấn công số mũ bí mật nhỏ.

### 5. `poc_implement/`

Các triển khai nâng cao minh họa lỗ hổng trong thực tế:

* **`code_signing/`**: Tấn công tính dẻo (malleability) của chữ ký và tấn công phát lại (replay).
* **`JWT_Confusion/`**: Tấn công nhầm lẫn thuật toán (Algorithm confusion) trong JWT token.
* **`wiener attack on JWT/`**: Áp dụng tấn công Wiener vào quy trình ký JWT.

---

## Các Kỹ thuật Tấn công Chính

| Loại tấn công | Chi tiết kỹ thuật |
| --- | --- |
| **1. Tấn công Toán học** | • Phân tích thừa số (GNFS, Pollard )<br><br>• Tấn công Wiener (số mũ bí mật nhỏ)<br><br>• Tấn công  Håstad<br><br>• Tấn công Modulus chung (Common modulus) |
| **2. Padding Oracle** | • Bleichenbacher (PKCS#1 v1.5)<br><br>• Tấn công Marvin (dựa trên thời gian)<br><br>• Tấn công Manger (OAEP) |
| **3. Lỗi Triển khai** | • Tấn công tiêm lỗi RSA-CRT<br><br>• Tấn công thời gian vào thuật toán lũy thừa module<br><br>• Điểm yếu của bộ sinh số ngẫu nhiên (RNG) |
| **4. Kịch bản Thực tế** | • Lỗ hổng trao đổi khóa RSA trong TLS 1.2<br><br>• Nhầm lẫn thuật toán JWT<br><br>• Tính dẻo trong Code signing<br><br>• Tấn công kênh kề trên HSM/TPM |

---

## Hướng dẫn Bắt đầu

### Yêu cầu tiên quyết

* **Docker:** Để chạy các môi trường lab.
* **Python 3:** Để chạy các script PoC.

### Chạy PoC (Exploit)

Mỗi thư mục PoC đều có file `README.md` riêng với hướng dẫn cụ thể.

### Sử dụng Docker Labs

```bash
cd docker/[ten_lab]
docker build -t [ten_lab] .
docker run [ten_lab]
```

### Tài liệu tham khảo

* Boneh, D. (1999). Twenty Years of Attacks on the RSA Cryptosystem
* Bleichenbacher, D. (1998). Chosen Ciphertext Attacks Against PKCS#1
* Kocher, P. (1996). Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS
* Và nhiều tài liệu khác được trích dẫn trong báo cáo đầy đủ.

---
*Dự án này phục vụ mục đích giáo dục. Vui lòng sử dụng có trách nhiệm và tuân thủ các quy định pháp luật hiện hành.*