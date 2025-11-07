# Cách chạy Wiener Attack PoC

### 1. Chạy Challenge 
```bash
python3 challenge_file.py
```
Khi chạy, chương trình sẽ hiển thị:
```
============================
      A RSA CHALLENGE      
============================
e = ...
n = ...
c = ...
```

**Lưu ý:** Có 5 lần thử nhập flag.

### 2. Chạy Wiener Attack
Mở một terminal và chạy lệnh sau:
```bash
python3 wiener_attack.py
```

Chương trình sẽ yêu cầu nhập 3 giá trị:
```
Enter e: [dán giá trị e từ challenge]
Enter n: [dán giá trị n từ challenge]  
Enter c: [dán giá trị c từ challenge]
```

### 3. Kết quả mong đợi
Nếu thành công, bạn sẽ thấy:
```
[+] Recovered p,q,d:
    p bitlen: 128
    q bitlen: 128
    d: 1123456789
[+] p * q == n: True
[+] Decrypted message: W1n{...}
```
Chúc bạn capture flag thành công! 
