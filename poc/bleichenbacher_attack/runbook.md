# Cách chạy PoC

1. Khởi động môi trường:
```bash
source .venv/bin/activate
```
2. Khởi động oracle server:
```bash
python oracle_server.py
```
3. Mở một terminal khác để chạy tấn công:
```bash
python bleichenbacher_attack.py
```
Có thể thử decode một plain text khác bằng cách thay đổi giá trị của biến `test_messages` (Ctrl+F) ở `bleichenbacher_attack.py`. Lưu ý, vì được thử nghiệm trên khóa 256-bit nên chỉ nhận tối đa 11 ký tự để ta có thể giải mã thành công.