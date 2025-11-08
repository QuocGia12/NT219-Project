#!/usr/bin/env python3
"""
oracle_server.py
Update: Server với RSA 512-bit + Session Secret
"""

import socket
import threading
import sys
import os
import binascii
import random
import math
import subprocess
import tempfile
import hashlib
import time

def generate_512bit_rsa():
    """Tạo key RSA 512-bit"""
    print("[+] Generating 512-bit RSA key...")
    
    try:
        # Tạo private key 512-bit bằng OpenSSL
        result = subprocess.run([
            'openssl', 'genrsa', '512'
        ], check=True, capture_output=True, text=True)
        
        private_key = result.stdout
        
        # Lưu tạm để parse
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as f:
            f.write(private_key)
            key_file = f.name
        
        # Parse bằng openssl rsa -text
        result_text = subprocess.run([
            'openssl', 'rsa', '-in', key_file, '-text', '-noout'
        ], capture_output=True, text=True, check=True)
        
        output = result_text.stdout
        
        # Parse hex values từ output
        hex_values = []
        current_hex = ""
        
        for line in output.split('\n'):
            line = line.strip()
            if ':' in line and not line.startswith('Private-Key') and not line.startswith('publicExponent'):
                hex_part = ""
                for part in line.split(':'):
                    part = part.strip()
                    if len(part) == 2 and all(c in '0123456789abcdefghiklmnopqrstuvwxyz' for c in part):
                        hex_part += part
                
                if hex_part:
                    current_hex += hex_part
            else:
                if current_hex:
                    hex_values.append(current_hex)
                    current_hex = ""
        
        if current_hex:
            hex_values.append(current_hex)
        
        # Lấy modulus và private exponent
        if len(hex_values) >= 3:
            n_hex = hex_values[0]
            e = 65537
            d_hex = hex_values[2]
        else:
            raise ValueError("Not enough hex values")
        
        n = int(n_hex, 16)
        d = int(d_hex, 16)
        
        if n.bit_length() < 500:
            raise ValueError(f"Modulus too small: {n.bit_length()} bits")
        
        print(f"[+] RSA key: {n.bit_length()} bits")
        return n, e, d
        
    except Exception as e:
        print(f"[-] OpenSSL error: {e}")
        # Fallback to Python
        return generate_512bit_rsa_python()

def generate_512bit_rsa_python():
    """Fallback: tạo RSA 512-bit bằng Python"""
    print("[+] Generating 512-bit RSA key using Python...")
    
    def is_prime(n, k=20):
        if n <= 1: return False
        if n <= 3: return True
        if n % 2 == 0: return False
        
        s, d = 0, n - 1
        while d % 2 == 0:
            s += 1
            d //= 2
        
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
        while True:
            p = random.getrandbits(bits)
            p |= (1 << (bits-1)) | 1
            if is_prime(p):
                return p
    
    p = generate_prime(256)
    q = generate_prime(256)
    n = p * q
    e = 65537
    phi = (p-1) * (q-1)
    d = pow(e, -1, phi)
    
    print(f"[+] Python RSA: {n.bit_length()} bits")
    return n, e, d

class OracleServer:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
        self.n, self.e, self.d = generate_512bit_rsa()
        self.k = (self.n.bit_length() + 7) // 8
        
        # SESSION SECRET - mục tiêu của attack
        self.session_secret = os.urandom(16)  # 128-bit session key
        self.session_id = random.randint(1, 1000000)
        
        print(f"[+] Server initialized:")
        print(f"    RSA: {self.n.bit_length()} bits, block size: {self.k} bytes")
        print(f"    Session ID: {self.session_id}")
        print(f"    Session Secret: {self.session_secret.hex()}")
    
    def pkcs1_v1_5_pad(self, message):
        """PKCS#1 v1.5 padding"""
        if len(message) > self.k - 11:
            raise ValueError(f"Message too long: {len(message)} > {self.k - 11}")
        
        padding_len = self.k - 3 - len(message)
        padding = bytes([random.randint(1, 255) for _ in range(padding_len)])
        
        padded = b'\x00\x02' + padding + b'\x00' + message
        return int.from_bytes(padded, byteorder='big')
    
    def pkcs1_v1_5_decrypt(self, ciphertext_int):
        """Giải mã PKCS#1 v1.5 và kiểm tra padding"""
        try:
            m = pow(ciphertext_int, self.d, self.n)
            m_bytes = m.to_bytes(self.k, byteorder='big')
            
            if m_bytes[0:2] == b'\x00\x02':
                if b'\x00' in m_bytes[2:]:
                    return True  # Padding hợp lệ
            return False  # Padding không hợp lệ
        except:
            return False
    
    def extract_plaintext(self, ciphertext_int):
        """Giải mã và trích xuất plaintext (dùng cho session handshake)"""
        try:
            m = pow(ciphertext_int, self.d, self.n)
            m_bytes = m.to_bytes(self.k, byteorder='big')
            
            if m_bytes[0:2] == b'\x00\x02':
                pos = m_bytes.find(b'\x00', 2)
                if pos != -1:
                    return m_bytes[pos + 1:]
            return None
        except:
            return None
    
    def handle_client_handshake(self, conn):
        """Xử lý handshake protocol"""
        try:
            # Bước 1: Gửi public key và session info
            conn.sendall(f"SESSION:{self.session_id}\n".encode())
            conn.sendall(f"MODULUS:{self.n:x}\n".encode())
            conn.sendall(f"EXPONENT:{self.e:x}\n".encode())
            
            # Bước 2: Nhận client hello (encrypted)
            data = conn.recv(1024).decode().strip()
            if data.startswith("CLIENT_HELLO:"):
                ciphertext_hex = data.split(":")[1]
                ciphertext_int = int(ciphertext_hex, 16)
                
                # Giải mã client hello
                client_hello = self.extract_plaintext(ciphertext_int)
                if client_hello and client_hello == b"ClientHello":
                    print(f"[+] Client hello accepted")
                    
                    # Bước 3: Gửi session secret (encrypted)
                    encrypted_secret = pow(self.pkcs1_v1_5_pad(self.session_secret), self.e, self.n)
                    conn.sendall(f"SESSION_SECRET:{encrypted_secret:x}\n".encode())
                    
                    return True
            
            return False
            
        except Exception as e:
            print(f"[-] Handshake error: {e}")
            return False
    
    def handle_client(self, conn, addr):
        """Xử lý client connection"""
        print(f"[+] Client connected: {addr}")
        
        try:
            # Thực hiện handshake
            if not self.handle_client_handshake(conn):
                conn.close()
                return
            
            print(f"[+] Handshake completed with {addr}")
            print(f"    Session {self.session_id} established")
            print(f"    Secret: {self.session_secret.hex()}")
            
            # Chế độ oracle: chỉ trả về 1/0 cho padding
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                
                try:
                    ciphertext_hex = data.decode().strip()
                    ciphertext_int = int(ciphertext_hex, 16)
                    
                    if self.pkcs1_v1_5_decrypt(ciphertext_int):
                        conn.sendall(b"1\n")  # Padding hợp lệ
                    else:
                        conn.sendall(b"0\n")  # Padding không hợp lệ
                except:
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
        print(f"[+] Session protocol enabled")
        print(f"[+] Ready for Bleichenbacher attack...")
        
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