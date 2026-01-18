## Cách chạy PoC

### 1. Khởi động servers:
```bash
# Terminal 1 - Oracle Server (Vulnerable)
python3 oracle_server.py

# Terminal 2 - Secure Server (Protected)
python3 secure_server.py
```

### 2. Chạy tấn công:
Mở một terminal khác, chạy tấn công:
```bash
python3 session_attack.py
```

### 3. Chọn server để tấn công:
```
SELECT SERVER TO ATTACK
==================================================
1 - Oracle Server (Port 9999) - VULNERABLE
    • Uses PKCS#1 v1.5
    • Vulnerable to Bleichenbacher
2 - Secure Server (Port 9990) - PROTECTED
    • Uses RSA-OAEP
    • Constant-time + Error hiding
```