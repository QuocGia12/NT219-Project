#!/usr/bin/env python3
# server_oracle.py (Marvin Edition)
#
# Mô phỏng thực tế: Chênh lệch thời gian đến từ việc CPU xử lý phép toán BigNum.
#
# Kịch bản:
# - Nếu Padding đúng: Server tiếp tục tính toán khóa phiên (Derive Key) -> Tốn CPU.
# - Nếu Padding sai: Server phát hiện sớm và dừng lại (hoặc tính toán giả nhưng nhẹ hơn) -> Ít tốn CPU.

import socket
import subprocess
import os
import random
from pathlib import Path

HOST = "0.0.0.0"
PORT = 9999

OPENSSL = "/opt/openssl-vuln/bin/openssl"
PRIVATE_KEY = "/app/private.key"
PUBLIC_KEY = "/app/public.pem"
SECRET_FILE = "/app/session_secret.bin"
CIPHERTEXT_FILE = "/app/c0.bin"

# --- CẤU HÌNH BIGNUM ĐỂ GÂY DELAY CPU ---
# Để tấn công qua mạng (network jitter) khả thi trong môi trường Lab Python,
# ta cần khuếch đại độ trễ này lên mức mili-seconds (thay vì nano-seconds).
#
# Ta sẽ dùng phép tính: result = pow(base, exponent, modulus)
# Với các số rất lớn (4096 bits).

def generate_huge_int(bits=4096):
    return random.getrandbits(bits)

# Tạo sẵn các số lớn trong bộ nhớ để không tính thời gian random vào thời gian xử lý
BIG_BASE = generate_huge_int()
BIG_EXP = generate_huge_int()
BIG_MOD = generate_huge_int()

WORKLOAD_LOOPS = 1

def cpu_heavy_task():
    """
    Mô phỏng việc tính toán nặng (VD: derive keys, HMAC, KDF)
    khi giải mã thành công.
    """
    x = BIG_BASE
    for _ in range(WORKLOAD_LOOPS):
        # Phép tính tốn CPU thực sự
        # PreSecretMaster = (Base ** Exponent) mod Modulus
        x = pow(x, BIG_EXP, BIG_MOD)
    return x

def run_cmd(cmd, input_bytes=None):
    res = subprocess.run(
        cmd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return res.returncode, res.stdout, res.stderr

def extract_n_e_from_private():
    rc, out, err = run_cmd([OPENSSL, "rsa", "-in", PRIVATE_KEY, "-text", "-noout"])
    if rc != 0: raise RuntimeError(f"openssl error: {err.decode()}")
    text = out.decode()
    lines = text.splitlines()
    n_hex_parts = []
    reading_modulus = False
    e_dec = None
    for line in lines:
        line = line.strip()
        if line.startswith("modulus:"):
            reading_modulus = True
            continue
        if reading_modulus:
            if line.startswith("publicExponent"): reading_modulus = False
            else: n_hex_parts.append(line.replace(":", "").replace(" ", ""))
        if line.startswith("publicExponent"):
            e_dec = int(line.split()[1])
    
    return int("".join(n_hex_parts), 16), e_dec

def generate_public_key():
    run_cmd([OPENSSL, "rsa", "-in", PRIVATE_KEY, "-pubout", "-out", PUBLIC_KEY])

def generate_session_secret_and_cipher():
    secret = os.urandom(32)
    Path(SECRET_FILE).write_bytes(secret)
    run_cmd([OPENSSL, "rsautl", "-encrypt", "-pubin", "-inkey", PUBLIC_KEY, "-pkcs", "-in", SECRET_FILE, "-out", CIPHERTEXT_FILE])
    return secret, Path(CIPHERTEXT_FILE).read_bytes()

def handle_client(conn, addr, n, e, c0_bytes):
    print(f"[+] Connected: {addr}")
    try:
        conn.sendall(f"MODULUS:{n:x}\n".encode())
        conn.sendall(f"EXPONENT:{e:x}\n".encode())
        conn.sendall(f"CIPHERTEXT:{c0_bytes.hex()}\n".encode())

        while True:
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk: break
                data += chunk
            if not data: break

            hex_str = data.strip().decode(errors="ignore")
            if not hex_str: continue

            try:
                c_bytes = bytes.fromhex(hex_str)
            except ValueError:
                conn.sendall(b"OK\n") # Fast fail
                continue

            # 1. Decrypt & Check Padding
            # OpenSSL binary chạy khá nhanh, độ trễ chủ yếu ở subprocess
            rc, out, err = run_cmd(
                [OPENSSL, "rsautl", "-decrypt", "-inkey", PRIVATE_KEY, "-pkcs"],
                input_bytes=c_bytes,
            )

            valid = (rc == 0)

            # 2. MARVIN SIMULATION LOGIC
            if valid:
                # CASE: Padding OK -> Server tiếp tục xử lý PreMasterSecret
                # Mô phỏng bằng cách tính toán nặng
                cpu_heavy_task()
            else:
                # CASE: Padding Fail -> Server dừng sớm
                # Không làm gì cả (hoặc làm việc rất nhẹ) -> Return nhanh
                pass

            conn.sendall(b"OK\n")

    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        conn.close()

def main():
    generate_public_key()
    n, e = extract_n_e_from_private()
    secret, c0 = generate_session_secret_and_cipher()
    
    print(f"[+] Server Ready. Math Loop Load: {WORKLOAD_LOOPS}")
    print(f"[+] Public Modulus (n): {n:x}")
    print(f"[+] Public Exponent (e): {e:x}")
    # print(f"[+] Ciphertext (c0): {c0.hex()}")
    # print(f"[+] Session Secret (for debug): {secret.hex()}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        while True:
            conn, addr = s.accept()
            handle_client(conn, addr, n, e, c0)

if __name__ == "__main__":
    main()