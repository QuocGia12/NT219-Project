## Mô tả
Code minh họa một **Fault Attack trên chữ ký RSA sử dụng CRT** (Chinese Remainder Theorem), thường được gọi là **Bellcore attack**.

Chương trình mô phỏng một server ký số RSA-CRT bị lỗi phần cứng (hoặc glitch) khi tính toán chữ ký modulo `p`, từ đó cho phép kẻ tấn công **khôi phục lại private key** chỉ với **một chữ ký đúng và một chữ ký lỗi**.

## Chi tiết 
Hàm `BugServer(m, fault)`: 
- Ký message `m` bằng RSA-CRT 
- Nếu `fault == 1`: giả lập lỗi bằng cách làm sai `s1`
- Trả về chữ ký `s`

Hàm `attack()`: thực hiện `RSA-CRT fault attack` trên BugServer, tính được được factors `p`, `q`, từ đó attacker tính được `d` và có thể giả mạo chữ ký của bất kỳ message nào. 

## Hướng dẫn chạy 
Tại thư mục `poc/RSA_CRT_fault_attack`:
```bash 
python attack.py 
```
## Nhận xét 
Nếu như attacker có thể thực hiện được fault trên phần cứng, lấy được chữ ký lỗi và chữ ký thật, việc tính `p` và `q` là rất nhanh. 
