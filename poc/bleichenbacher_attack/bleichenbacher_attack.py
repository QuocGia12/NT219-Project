#!/usr/bin/env python3
"""
bleichenbacher_attack.py
"""

import sys
sys.set_int_max_str_digits(100000) 

import socket
import binascii
import time
import random

class CorrectBleichenbacher:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.socket = None
        self.n = None
        self.e = None
        self.B = None
        self.k = None
        
    def connect(self):
        """Kết nối server"""
        print(f"[*] Connecting to {self.host}:{self.port}")
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))
            
            # Nhận public key
            n_hex = self.socket.recv(256).decode().strip()
            e_hex = self.socket.recv(256).decode().strip()
            
            self.n = int(n_hex, 16)
            self.e = int(e_hex, 16)
            self.k = (self.n.bit_length() + 7) // 8
            self.B = 2 ** (8 * (self.k - 2))  # B = 2^(8*(k-2))
            
            print(f"[+] Received {self.n.bit_length()}-bit key")
            print(f"    n = {self.n}")
            print(f"    k = {self.k} bytes, B = 2^({8*(self.k-2)}) = {self.B}")
            return True
            
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return False
    
    def query_oracle(self, ciphertext_int):
        """Gửi query đến oracle"""
        try:
            c_bytes = ciphertext_int.to_bytes(self.k, byteorder='big')
            c_hex = binascii.hexlify(c_bytes).decode()
            
            self.socket.sendall((c_hex + "\n").encode())
            response = self.socket.recv(32).decode().strip()
            
            return response == "1"
        except Exception as e:
            return False
    
    def pkcs1_pad(self, message):
        """Tạo PKCS#1 v1.5 padding"""
        if len(message) > self.k - 11:
            raise ValueError(f"Message too long for PKCS#1 padding: {len(message)} > {self.k - 11}")
        
        padding_len = self.k - 3 - len(message)
        padding = bytes([random.randint(1, 255) for _ in range(padding_len)])
        
        padded = b'\x00\x02' + padding + b'\x00' + message
        return int.from_bytes(padded, byteorder='big')
    
    def ceil(self, a, b):
        """Làm tròn lên a/b"""
        return (a + b - 1) // b
    
    def floor(self, a, b):
        """Làm tròn xuống a/b"""
        return a // b
    
    def step1_find_s0(self, c0):
        """Bước 1: Tìm s0 đầu tiên sao cho c0 * s0^e có padding hợp lệ"""
        print(f"[*] Step 1: Finding initial s0")
        
        s = self.ceil(self.n, 3 * self.B)
        count = 0
        
        while True:
            c_prime = (c0 * pow(s, self.e, self.n)) % self.n
            
            if self.query_oracle(c_prime):
                print(f"[+] Found s0 = {s} after {count} queries")
                return s
            
            s += 1
            count += 1
            
            if count % 100000 == 0:
                print(f"    ... tried {count} values")
    
    def step2_narrow(self, c0, s, M):
        """Bước 2: Thu hẹp tập M dựa trên s"""
        B2 = 2 * self.B
        B3 = 3 * self.B
        new_M = set()
        
        for (a, b) in M:
            # Tìm tất cả r thỏa mãn: r >= ceil((a*s - B3 + 1)/n) 
            # và r <= floor((b*s - B2)/n)
            r_min = self.ceil(a * s - B3 + 1, self.n)
            r_max = self.floor(b * s - B2, self.n)
            
            for r in range(r_min, r_max + 1):
                # Với mỗi r, tìm khoảng mới
                low = max(a, self.ceil(B2 + r * self.n, s))
                high = min(b, self.floor(B3 - 1 + r * self.n, s))
                
                if low <= high:
                    new_M.add((low, high))
        
        return new_M
    
    def step3_find_next_s(self, c0, M, s_prev):
        """Bước 3: Tìm s tiếp theo"""
        if len(M) > 1:
            # Nhiều khoảng - tìm s nhỏ nhất > s_prev
            s = s_prev + 1
            while True:
                c_prime = (c0 * pow(s, self.e, self.n)) % self.n
                if self.query_oracle(c_prime):
                    return s
                s += 1
        else:
            # Một khoảng [a, b]
            a, b = next(iter(M))
            
            # Tìm r >= ceil(2*(b*s_prev - 2*B)/n
            r = self.ceil(2 * (b * s_prev - 2 * self.B), self.n)
            
            while True:
                # Tìm s trong [ceil((2*B + r*n)/b), floor((3*B + r*n)/a)]
                s_low = self.ceil(2 * self.B + r * self.n, b)
                s_high = self.floor(3 * self.B + r * self.n, a)
                
                for s in range(s_low, s_high + 1):
                    c_prime = (c0 * pow(s, self.e, self.n)) % self.n
                    if self.query_oracle(c_prime):
                        return s
                
                r += 1
    
    def extract_plaintext(self, m_int):
        """Trích xuất plaintext từ integer đã giải mã"""
        try:
            m_bytes = m_int.to_bytes(self.k, byteorder='big')
            
            # Kiểm tra định dạng PKCS#1 v1.5
            if m_bytes[0:2] == b'\x00\x02':
                # Tìm byte 0x00 phân cách
                pos = m_bytes.find(b'\x00', 2)
                if pos != -1:
                    message = m_bytes[pos + 1:]
                    print(f"[DEBUG] Extracted raw: {message} (length: {len(message)})")  # <-- THÊM DÒNG NÀY
                    return message
            return None
        except:
            return None
    
    def attack(self, plaintext):
        """Thực hiện tấn công Bleichenbacher hoàn chỉnh"""
        print(f"\n[*] Starting Bleichenbacher attack for: {plaintext}")
        
        # Tạo bản mã gốc
        m0 = self.pkcs1_pad(plaintext)
        c0 = pow(m0, self.e, self.n)
        
        print(f"[+] Created original ciphertext")
        print(f"    m0 (padded) = {m0}")
        print(f"    c0 = {c0}")
        
        # Bước 1: Khởi tạo
        B2 = 2 * self.B
        B3 = 3 * self.B
        M = {(B2, B3 - 1)}  # Khoảng ban đầu
        
        print(f"[*] Initial interval: [{B2}, {B3-1}]")
        
        # Bước 2: Tìm s0 đầu tiên
        s = self.step1_find_s0(c0)
        
        # Bước 3: Thu hẹp với s0
        M = self.step2_narrow(c0, s, M)
        print(f"[*] After s0: {len(M)} intervals")
        
        # Bước 4: Lặp cho đến khi tìm được plaintext
        iteration = 1
        max_iterations = 50000
        
        while iteration <= max_iterations:
            print(f"\n  [Iteration {iteration}]")
            
            # Tìm s tiếp theo
            s_prev = s
            s = self.step3_find_next_s(c0, M, s_prev)
            # print(f"    Found s = {s}")
            
            # Thu hẹp khoảng với s mới
            M_new = self.step2_narrow(c0, s, M)
            print(f"    Intervals: {len(M_new)}")
            
            # Kiểm tra nếu chỉ còn một điểm
            if len(M_new) == 1:
                a, b = next(iter(M_new))
                if a == b:
                    print(f"    [+] Single point found: {a}")
                    recovered = self.extract_plaintext(a)
                    if recovered:
                        print(f"    Extracted: {recovered}")
                        if recovered == plaintext:
                            return recovered
            
            M = M_new
            iteration += 1
            
            # In khoảng đầu tiên để debug
            if M:
                a, b = next(iter(M))
                print(f"    First interval: [{a}, {b}]")
        
        # Nếu vòng lặp kết thúc, thử tất cả các điểm trong khoảng cuối
        if len(M) == 1:
            a, b = next(iter(M))
            print(f"[*] Searching in final interval: [{a}, {b}]")
            
            for m_candidate in range(a, min(b + 1, a + 1000)):  # Giới hạn tìm kiếm
                recovered = self.extract_plaintext(m_candidate)
                if recovered and recovered == plaintext:
                    return recovered
        
        return None
    
    def close(self):
        """Đóng kết nối"""
        if self.socket:
            self.socket.close()

def main():
    print("BLEICHENBACHER ATTACK")
    print("============================================")
    
    attack = CorrectBleichenbacher('127.0.0.1', 9999)
    
    try:
        if attack.connect():
            # Test với các message
            test_messages = [b"hello world"]
            
            for msg in test_messages:
                print(f"\n{'='*60}")
                print(f"ATTACKING: {msg}")
                print(f"{'='*60}")
                
                start_time = time.time()
                result = attack.attack(msg)
                end_time = time.time()
                
                if result:
                    print(f"\n [v] SUCCESS! Plaintext: {result}")
                    print(f"   Time: {end_time - start_time:.2f} seconds")
                    
                    if result == msg:
                        print("  ✓ Exact match!")
                        break
                else:
                    print(f"\n [x] Failed to recover: {msg}")
                    print(f"   Time: {end_time - start_time:.2f} seconds")
                    
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        attack.close()

if __name__ == "__main__":
    main()