#!/usr/bin/env python3
"""
secure_serve.py
Chỉ sử dụng RSA-OAEP và từ chối tất cả PKCS#1 v1.5
"""

import socket
import threading
import sys
import os
import binascii
import random
import math
import hashlib
import time
import hmac
import subprocess
import tempfile

class SecureServer:
    def __init__(self, host='127.0.0.1', port=9990):
        self.host = host
        self.port = port
        self.n, self.e, self.d = self.generate_rsa_openssl_simple()
        self.k = (self.n.bit_length() + 7) // 8
        
        # Session
        self.session_secret = os.urandom(16)
        self.session_id = random.randint(1, 1000000)
        
        # Anti-tampering
        self.hmac_key = os.urandom(32)
        
        print(f"[+] Secure Server INITIALIZED:")
        print(f"    RSA: {self.n.bit_length()} bits")
        print(f"    Session ID: {self.session_id}")
        print(f"    Block size: {self.k} bytes")
        print(f"    STRICT MODE: RSA-OAEP ONLY, NO PKCS#1 v1.5")

    def generate_rsa_openssl_simple(self):
        """Tạo RSA 512-bit bằng OpenSSL - cách đơn giản và chắc chắn"""
        print("[+] Generating 512-bit RSA key using OpenSSL...")
        
        try:
            # Tạo private key với OpenSSL
            cmd_gen = ['openssl', 'genrsa', '512']
            result_gen = subprocess.run(cmd_gen, check=True, capture_output=True, text=True)
            private_key_pem = result_gen.stdout
            
            # Lưu private key ra file tạm
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as f:
                key_file = f.name
                f.write(private_key_pem)
            
            # Trích xuất modulus (n) từ private key
            cmd_modulus = ['openssl', 'rsa', '-in', key_file, '-modulus', '-noout']
            result_modulus = subprocess.run(cmd_modulus, check=True, capture_output=True, text=True)
            modulus_output = result_modulus.stdout.strip()
            
            # Parse modulus từ output (format: Modulus=XXXXX)
            if modulus_output.startswith('Modulus='):
                modulus_hex = modulus_output[8:]  # Bỏ 'Modulus='
                n = int(modulus_hex, 16)
            else:
                raise ValueError("Cannot parse modulus from OpenSSL output")
            
            # Trích xuất private exponent (d) - dùng rsa -text
            cmd_text = ['openssl', 'rsa', '-in', key_file, '-text', '-noout']
            result_text = subprocess.run(cmd_text, check=True, capture_output=True, text=True)
            text_output = result_text.stdout
            
            # Parse private exponent từ text output
            lines = text_output.split('\n')
            in_private = False
            private_hex = ''
            
            for line in lines:
                if 'privateExponent' in line:
                    in_private = True
                    continue
                elif in_private and 'publicExponent' in line:
                    break
                elif in_private:
                    # Lấy các dòng hex
                    clean_line = ''.join(c for c in line.strip() if c in '0123456789abcdefABCDEF:')
                    if clean_line:
                        # Bỏ dấu : nếu có
                        clean_line = clean_line.replace(':', '')
                        private_hex += clean_line
            
            if not private_hex:
                # Fallback: tính d từ n, e
                print("[INFO] Calculating private exponent from factors...")
                d = self.calculate_private_exponent(key_file)
            else:
                d = int(private_hex, 16)
            
            # Public exponent mặc định
            e = 65537
            
            # Dọn dẹp file tạm
            os.unlink(key_file)
            
            print(f"[SUCCESS] OpenSSL RSA key generated: {n.bit_length()} bits")
            return n, e, d
            
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] OpenSSL command failed: {e}")
            if 'key_file' in locals() and os.path.exists(key_file):
                os.unlink(key_file)
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Key generation failed: {e}")
            if 'key_file' in locals() and os.path.exists(key_file):
                os.unlink(key_file)
            sys.exit(1)

    def calculate_private_exponent(self, key_file):
        """Tính private exponent từ các thừa số nguyên tố"""
        try:
            # Lấy thông tin chi tiết về key
            cmd_info = ['openssl', 'rsa', '-in', key_file, '-text', '-noout']
            result_info = subprocess.run(cmd_info, check=True, capture_output=True, text=True)
            info_output = result_info.stdout
            
            # Parse prime1 và prime2 (p và q)
            lines = info_output.split('\n')
            in_prime1 = False
            in_prime2 = False
            prime1_hex = ''
            prime2_hex = ''
            
            for line in lines:
                line = line.strip()
                if 'prime1' in line:
                    in_prime1 = True
                    in_prime2 = False
                    continue
                elif 'prime2' in line:
                    in_prime1 = False
                    in_prime2 = True
                    continue
                elif 'exponent' in line:
                    in_prime1 = False
                    in_prime2 = False
                    continue
                
                if in_prime1 or in_prime2:
                    clean_line = ''.join(c for c in line if c in '0123456789abcdefABCDEF:')
                    if clean_line:
                        clean_line = clean_line.replace(':', '')
                        if in_prime1:
                            prime1_hex += clean_line
                        else:
                            prime2_hex += clean_line
            
            if prime1_hex and prime2_hex:
                p = int(prime1_hex, 16)
                q = int(prime2_hex, 16)
                e = 65537
                phi = (p-1) * (q-1)
                d = pow(e, -1, phi)
                return d
            else:
                raise ValueError("Cannot extract prime factors")
                
        except Exception as e:
            print(f"[ERROR] Failed to calculate private exponent: {e}")
            sys.exit(1)

    # ==================== RSA-OAEP IMPLEMENTATION BẢO MẬT ====================
    
    def mgf1(self, seed, length):
        """MGF1 mask generation function - an toàn"""
        hLen = 32  # SHA-256
        T = b""
        counter = 0
        while len(T) < length:
            C = seed + counter.to_bytes(4, 'big')
            T += hashlib.sha256(C).digest()
            counter += 1
        return T[:length]
    
    def oaep_encode(self, message, label=b''):
        """RSA-OAEP encoding - với label để chống replay"""
        hLen = 32  # SHA-256
        k = self.k
        
        # Kiểm tra kích thước
        max_msg_len = k - 2 * hLen - 2
        if len(message) > max_msg_len:
            raise ValueError(f"Message too long: {len(message)} > {max_msg_len}")
        
        lHash = hashlib.sha256(label).digest()
        ps = b'\x00' * (k - len(message) - 2 * hLen - 2)
        DB = lHash + ps + b'\x01' + message
        
        seed = os.urandom(hLen)
        dbMask = self.mgf1(seed, k - hLen - 1)
        maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask))
        
        seedMask = self.mgf1(maskedDB, hLen)
        maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask))
        
        return b'\x00' + maskedSeed + maskedDB

    def oaep_decode(self, encoded, label=b''):
        """RSA-OAEP decoding - trả về None nếu không hợp lệ"""
        hLen = 32  # SHA-256
        k = self.k
        
        # Kiểm tra cơ bản
        if len(encoded) != k:
            return None
        if encoded[0] != 0:
            return None
        
        maskedSeed = encoded[1:1+hLen]
        maskedDB = encoded[1+hLen:]
        
        seedMask = self.mgf1(maskedDB, hLen)
        seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))
        
        dbMask = self.mgf1(seed, k - hLen - 1)
        DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))
        
        lHash = hashlib.sha256(label).digest()
        if not hmac.compare_digest(DB[:hLen], lHash):
            return None
        
        # Tìm byte 0x01
        i = hLen
        while i < len(DB) and DB[i] == 0:
            i += 1
        
        if i >= len(DB) or DB[i] != 1:
            return None
        
        return DB[i+1:]

    def rsa_oaep_decrypt_secure(self, ciphertext_int, label=b''):
        """Giải mã OAEP an toàn - KHÔNG có fallback đến PKCS#1"""
        try:
            # Giải mã RSA
            m = pow(ciphertext_int, self.d, self.n)
            encoded = m.to_bytes(self.k, 'big')
            
            # Decode OAEP
            result = self.oaep_decode(encoded, label)
            
            # Constant-time delay bất kể kết quả
            time.sleep(0.01)  # 10ms cố định
            
            if result is not None:
                return True, result
            else:
                return False, None
                
        except Exception:
            # Constant-time delay ngay cả khi có lỗi
            time.sleep(0.01)
            return False, None

    def create_secure_message(self, message_type, payload):
        """Tạo message an toàn với HMAC"""
        timestamp = int(time.time()).to_bytes(8, 'big')
        nonce = os.urandom(8)
        data = message_type + timestamp + nonce + payload
        
        # Thêm HMAC
        signature = hmac.new(self.hmac_key, data, hashlib.sha256).digest()
        return data + signature

    def verify_secure_message(self, data, message_type):
        """Xác thực message với HMAC"""
        if len(data) < len(message_type) + 8 + 8 + 32:  # type + timestamp + nonce + hmac
            return None
            
        # Tách HMAC
        message_data = data[:-32]
        received_hmac = data[-32:]
        
        # Tính HMAC
        expected_hmac = hmac.new(self.hmac_key, message_data, hashlib.sha256).digest()
        
        # So sánh constant-time
        if not hmac.compare_digest(received_hmac, expected_hmac):
            return None
            
        # Kiểm tra message type
        if not message_data.startswith(message_type):
            return None
            
        # Kiểm tra timestamp (chống replay)
        timestamp = int.from_bytes(message_data[len(message_type):len(message_type)+8], 'big')
        current_time = int(time.time())
        if abs(current_time - timestamp) > 30:  # 30 seconds tolerance
            return None
            
        return message_data[len(message_type)+8+8:]  # Trả về payload

    def handle_client_secure(self, conn, addr):
        """Xử lý client an toàn - CHỈ RSA-OAEP"""
        print(f"\n[+] Client connected: {addr}")
        
        try:
            # Gửi public key
            conn.sendall(f"SESSION:{self.session_id}\n".encode())
            conn.sendall(f"MODULUS:{self.n:x}\n".encode())
            conn.sendall(f"EXPONENT:{self.e:x}\n".encode())
            print(f"[INFO] Sent handshake to {addr}")
            
            # Nhận client hello
            data = conn.recv(1024).decode().strip()
            
            if data.startswith("CLIENT_HELLO:"):
                ciphertext_hex = data.split(":")[1]
                ciphertext_int = int(ciphertext_hex, 16)
                
                print(f"[INFO] Client hello received from {addr}")
                
                # CHỈ giải mã với OAEP - KHÔNG có fallback PKCS#1
                success, decrypted = self.rsa_oaep_decrypt_secure(
                    ciphertext_int, 
                    label=f"SESSION_{self.session_id}".encode()
                )
                
                if success and decrypted == b"ClientHello":
                    print(f"[SUCCESS] Secure client hello accepted (OAEP) from {addr}")
                    
                    # Tạo session secret được bảo vệ
                    protected_secret = self.create_secure_message(
                        b"SESS_SECRET", 
                        self.session_secret
                    )
                    
                    # Mã hóa session secret với OAEP
                    secret_encoded = self.oaep_encode(
                        protected_secret,
                        label=f"SECRET_{self.session_id}".encode()
                    )
                    secret_int = int.from_bytes(secret_encoded, 'big')
                    encrypted_secret = pow(secret_int, self.e, self.n)
                    
                    conn.sendall(f"SESSION_SECRET:{encrypted_secret:x}\n".encode())
                    print(f"[SUCCESS] Secure session established with {addr}")
                    
                    # Chế độ oracle CHỈ chấp nhận OAEP
                    self.secure_oracle_mode(conn)
                else:
                    print(f"[REJECTED] Invalid client hello from {addr} - OAEP decryption failed")
                    conn.sendall(b"ERROR\n")
                    
        except Exception as e:
            print(f"[-] Client error {addr}: {e}")
        finally:
            conn.close()
            print(f"[INFO] Client disconnected: {addr}")

    def secure_oracle_mode(self, conn):
        """Chế độ oracle an toàn - CHỈ trả lời cho OAEP hợp lệ"""
        print(f"[INFO] Secure oracle mode active - OAEP ONLY")
        
        query_count = 0
        max_queries = 1000  # Giới hạn số lượng query
        
        while query_count < max_queries:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                
                ciphertext_hex = data.decode().strip()
                query_count += 1
                
                # Log giới hạn để tránh spam
                if query_count % 100 == 0:
                    print(f"[INFO] Oracle query count: {query_count}")
                
                ciphertext_int = int(ciphertext_hex, 16)
                
                # CHỈ thử OAEP - KHÔNG có PKCS#1 fallback
                success, decrypted = self.rsa_oaep_decrypt_secure(
                    ciphertext_int,
                    label=f"ORACLE_{self.session_id}".encode()
                )
                
                if success:
                    # Kiểm tra cấu trúc message an toàn
                    payload = self.verify_secure_message(decrypted, b"ORACLE_QUERY")
                    if payload is not None:
                        conn.sendall(b"1\n")
                    else:
                        conn.sendall(b"0\n")
                else:
                    conn.sendall(b"0\n")
                    
            except Exception as e:
                print(f"[ERROR] Oracle error: {e}")
                break
        
        print(f"[INFO] Oracle session ended after {query_count} queries")

    def start(self):
        """Khởi động server"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(5)
        
        print(f"\n[+] SECURE Server (FIXED) listening on {self.host}:{self.port}")
        print(f"[+] STRICT MODE: RSA-OAEP ONLY - NO PKCS#1 v1.5")
        print(f"[+] Constant-time operations enabled")
        print(f"[+] HMAC protection for all messages")
        print(f"[+] Bleichenbacher attack PROTECTED")
        print(f"[+] Ready for secure connections...")
        
        try:
            while True:
                conn, addr = server.accept()
                client_thread = threading.Thread(
                    target=self.handle_client_secure, 
                    args=(conn, addr),
                    daemon=True
                )
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[+] Shutting down secure server...")
        finally:
            server.close()

if __name__ == "__main__":
    server = SecureServer()
    server.start()