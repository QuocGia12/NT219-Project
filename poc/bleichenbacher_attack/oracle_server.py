#!/usr/bin/env python3
"""
oracle_server_256bit.py
Server với key RSA 256-bit được tạo thủ công
"""

import socket
import threading
import sys
import os
import binascii
import random
import math

# Tạo key RSA 256-bit thủ công
def generate_256bit_rsa():
    """Tạo key RSA 256-bit thủ công"""
    print("[+] Generating 256-bit RSA key...")
    
    # Tìm 2 số nguyên tố khoảng 2^64
    def is_prime(n, k=20):
        """Kiểm tra số nguyên tố với Miller-Rabin"""
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False
            
        # Viết n-1 = 2^s * d
        s = 0
        d = n - 1
        while d % 2 == 0:
            s += 1
            d //= 2
            
        # Kiểm tra k lần
        for _ in range(k):
            a = random.randint(2, n-2)
            x = pow(a, d, n)
            if x == 1 or x == n-1:
                continue
            for _ in range(s-1):
                x = pow(x, 2, n)
                if x == n-1:
                    break
            else:
                return False
        return True
    
    def generate_prime(bits):
        """Tạo số nguyên tố"""
        while True:
            p = random.getrandbits(bits)
            p |= (1 << (bits-1)) | 1  # Đảm bảo bit cao nhất là 1 và là số lẻ
            if is_prime(p):
                return p
    
    # Tạo p và q (mỗi số ~128 bit)
    p = generate_prime(128)
    q = generate_prime(128)
    
    # Tính n = p * q
    n = p * q
    
    # e thường dùng
    e = 65537
    
    # Tính phi(n) = (p-1)*(q-1)
    phi = (p-1) * (q-1)
    
    # Tính d = e^(-1) mod phi(n)
    d = pow(e, -1, phi)
    
    print(f"[+] Key generated:")
    print(f"    p = {p}")
    print(f"    q = {q}") 
    print(f"    n = {n} ({n.bit_length()} bits)")
    print(f"    e = {e}")
    print(f"    d = {d}")
    
    return n, e, d

class OracleServer:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.n, self.e, self.d = generate_256bit_rsa()
        self.k = (self.n.bit_length() + 7) // 8  # Độ dài modulus tính bằng bytes
    
    def pkcs1_v1_5_decrypt(self, ciphertext_int):
        """Giải mã PKCS#1 v1.5 và kiểm tra padding"""
        try:
            # Giải mã
            m = pow(ciphertext_int, self.d, self.n)
            
            # Chuyển sang bytes
            m_bytes = m.to_bytes(self.k, byteorder='big')
            
            # Kiểm tra định dạng PKCS#1 v1.5
            if m_bytes[0:2] == b'\x00\x02':
                # Tìm byte 0x00 phân cách
                if b'\x00' in m_bytes[2:]:
                    return True  # Padding hợp lệ
            return False  # Padding không hợp lệ
            
        except:
            return False
    
    def handle_client(self, conn, addr):
        """Xử lý client"""
        print(f"[+] Client connected: {addr}")
        
        try:
            # Gửi public key
            conn.sendall(f"{self.n:x}\n".encode())
            conn.sendall(f"{self.e:x}\n".encode())
            
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                
                # Xử lý ciphertext
                try:
                    ciphertext_hex = data.decode().strip()
                    ciphertext_int = int(ciphertext_hex, 16)
                    
                    # Kiểm tra padding
                    if self.pkcs1_v1_5_decrypt(ciphertext_int):
                        conn.sendall(b"1\n")
                    else:
                        conn.sendall(b"0\n")
                        
                except Exception as e:
                    conn.sendall(b"ERR\n")
                    
        except Exception as e:
            print(f"[-] Client error {addr}: {e}")
        finally:
            conn.close()
            print(f"[+] Client disconnected: {addr}")
    
    def start(self):
        """Khởi động server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        
        print(f"[+] Oracle server listening on {self.host}:{self.port}")
        print(f"[+] Using 256-bit RSA key")
        
        try:
            while True:
                conn, addr = server.accept()
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(conn, addr),
                    daemon=True
                )
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[+] Shutting down server...")
        finally:
            server.close()

if __name__ == "__main__":
    server = OracleServer()
    server.start()