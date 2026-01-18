# Proof of Concept: Wiener Attack on RSA với Small Private Exponent

## Mục tiêu
Triển khai tấn công Wiener trên RSA khi private exponent `d` quá nhỏ, chứng minh khả năng khôi phục private key chỉ từ public key mà không cần phân tích thừa số.

## Tổng quan
Tấn công Wiener khai thác trường hợp private exponent `d` trong RSA quá nhỏ so với modulus `n`. Khi `d < (n^0.25)/3`, attacker có thể khôi phục private key thông qua **phân tích phân số liên tục** (continued fractions).

## Kiến trúc hệ thống
### 1. Wiener Attacker (`wiener_attack.py`)
- Nhận public key (n, e).
- Thực hiện tấn công Wiener để tìm private key.
- Giải mã ciphertext bằng private key tìm được.

## Thuật toán tấn công

### Các bước chính:

1. **Phân tích phân số liên tục**
   - Biểu diễn `e/n` dưới dạng phân số liên tục.
   - Tìm các convergent (phân số xấp xỉ) của `e/n`.

2. **Kiểm tra các convergent**
   - Với mỗi convergent `k/d` của `e/n`:
     - Kiểm tra xem `d` có phải là private key không.
     - Tính `φ(n) = (e×d - 1)/k`.
     - Giải phương trình bậc 2: `x² - (n - φ(n) + 1)x + n = 0`.

3. **Xác nhận kết quả**
   - Nếu tìm được `p` và `q` thỏa `p×q = n`.
   - Thì `d` chính là private exponent cần tìm.

### Code minh họa:
```python
def wiener_attack(n, e):
    # Phân tích phân số liên tục của e/n
    cf = cont_frac(e, n)
    convs = convergents_from_cf(cf)
    
    for k, d in convs:
        if k == 0: continue
        
        # Kiểm tra điều kiện
        if (e * d - 1) % k != 0: continue
        
        phi = (e * d - 1) // k
        # Giải phương trình x² - (n - phi + 1)x + n = 0
        s = n - phi + 1
        disc = s*s - 4*n
        
        if disc >= 0 and is_perfect_square(disc):
            t = math.isqrt(disc)
            p = (s + t) // 2
            q = (s - t) // 2
            if p * q == n:
                return p, q, d
    return None
```
### Nhận xét:
- Attack cực kỳ hiệu quả khi `d` nhỏ.
- Thời gian thực hiện rất nhanh.
- Không cần brute force hay phân tích thừa số phức tạp.

## Ứng dụng thực tế

Wiener attack không chỉ là lý thuyết mà có ứng dụng thực tế quan trọng:

1. **Phát hiện lỗ hổng trong thư viện RSA**
   - Kiểm tra xem thư viện crypto có tạo `d` quá nhỏ không.
   - Audit code RSA trong các ứng dụng.

2. **Phân tích malware**
   - Malware đôi khi dùng RSA với `d` nhỏ để tiết kiệm bộ nhớ.
   - Có thể break encryption của malware.

3. **Hệ thống nhúng (IoT)**
   - Thiết bị IoT thường dùng `d` nhỏ để tính toán nhanh.
   - Dễ bị tấn công Wiener.

### Tuy nhiên, hạn chế:
- **Điều kiện**: Chỉ work khi `d < n^0.25`.
- **Hiện đại**: Các thư viện hiện đại đã fix (luôn dùng `d` đủ lớn).
- **Không phổ biến**: Ít gặp trong thực tế hơn các attack khác.

## Biện pháp phòng thủ

- **Luôn dùng `d` đủ lớn**: `d > (n^0.25)/3`.
- **Dùng public exponent tiêu chuẩn**: e = 65537.
- **Kiểm tra key**: Verify private key trước khi dùng.
- **Thư viện chuẩn**: Dùng thư viện crypto đã được audit.

## Kết luận

PoC chứng minh thành công:
- Wiener attack hiệu quả khi `d` nhỏ.
- Có thể khôi phục hoàn toàn private key từ public key.