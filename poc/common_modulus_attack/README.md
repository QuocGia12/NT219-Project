## Giới thiệu 
Code mô phỏng một unsecure server thực hiện mã hóa một plaintext 2 lần với `e` khác nhau và `n` giống nhau. Từ đó đủ điều kiện để thực hiện **commom_modulus_attack**
- Hàm `encrypt(pt)`: thực hiện mã hóa một plaintext `pt` 2 lần với `e` khác nhau(`e1` và `e2`) và `n` giống nhau, ciphertext tương ứng là `ct1` và `ct2` 
- Hàm `attack(n, e1, e2, ct1, ct2)` thực hiện **commom_modulus_attack** để khôi phục plaintext `pt` từ các tham số tạo từ hàm `encrypt(pt)`
## Hướng dẫn chạy 
Tại thư mục `/poc/commom_modulus_attack`
```bash
python main.py
```
## Nhận xét 
Nếu như có đầy đủ tham số cần thiết thì hàm `attack(n1, n2, n3, ct1, ct2, ct3)` thực hiện tấn công rất nhanh. kết quả là attacker khôi phục được plaintext, plaintext này có thể là premaster secret, từ đó attacker tính được session key, đọc được toàn bộ gói tin gửi đi trong session đó. 