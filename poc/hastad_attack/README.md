## Giới thiệu
Code mô phỏng một unsecure server thực hiện việc mã hóa với public exponent nhỏ: `e = 3`
## Chi tiết 
- Hàm `encrypt(pt)` mô phỏng việc server mã hóa cùng một plaintext `pt` với 3 public key `n` khác nhau(`n1`, `n2`, `n3`), 3 ciphertext tương ứng là `ct1`, `ct2`, `ct3`
- Hàm `HastadAttack(n1, n2, n3, ct1, ct2, ct3)` thực hiện Hastad Attack để khôi phục plaintext `pt` từ các tham số tạo từ hàm `encrypt(pt)`
## Hướng dẫn chạy 
Tại thư mục `/poc/hastad_attack`
```bash
python main.py
```
## Nhận xét 
Nếu như có đầy đủ tham số cần thiết thì hàm `HastadAttack(n1, n2, n3, ct1, ct2, ct3)` thực hiện tấn công rất nhanh. kết quả là attacker khôi phục được plaintext, plaintext này có thể là premaster secret, từ đó attacker tính được session key, đọc được toàn bộ gói tin gửi đi trong session đó. 