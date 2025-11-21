#!/usr/bin/env python3
# server_oracle.py
#
# Oracle server dùng OpenSSL vulnerable build (1.1.1q).
# - Start: tạo public.pem, session_secret.bin, c0.bin bằng /opt/openssl-vuln/bin/openssl
# - Gửi cho client: MODULUS, EXPONENT, CIPHERTEXT (c0)
# - Oracle loop:
#     + Nhận ciphertext hex
#     + Dùng openssl rsautl -decrypt -pkcs để check padding
#     + Nếu valid: sleep lâu hơn, rồi gửi "OK"
#     + Nếu invalid: sleep nhanh, gửi "OK"
#
# => Attacker chỉ thấy TIME khác nhau, không thấy bit 1/0.

import socket
import subprocess
import time
import os
from pathlib import Path

HOST = "0.0.0.0"
PORT = 9999

OPENSSL = "/opt/openssl-vuln/bin/openssl"
PRIVATE_KEY = "/app/private.key"
PUBLIC_KEY = "/app/public.pem"
SECRET_FILE = "/app/session_secret.bin"
CIPHERTEXT_FILE = "/app/c0.bin"

VALID_DELAY = 0.050   # 50 ms
INVALID_DELAY = 0.005 # 5 ms


def run_cmd(cmd, input_bytes=None):
    """Chạy lệnh và trả (returncode, stdout, stderr)."""
    res = subprocess.run(
        cmd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return res.returncode, res.stdout, res.stderr


def extract_n_e_from_private():
    """
    Dùng 'openssl rsa -text -noout' để lấy modulus (n) và publicExponent (e).
    """
    rc, out, err = run_cmd([OPENSSL, "rsa", "-in", PRIVATE_KEY, "-text", "-noout"])
    if rc != 0:
        raise RuntimeError(f"openssl rsa -text failed: {err.decode()}")

    text = out.decode()
    lines = text.splitlines()

    # modulus lines bắt đầu sau "modulus:"
    n_hex_parts = []
    reading_modulus = False
    e_dec = None

    for line in lines:
        line = line.strip()
        if line.startswith("modulus:"):
            reading_modulus = True
            continue
        if reading_modulus:
            if line.startswith("publicExponent"):
                reading_modulus = False
            else:
                # dòng modulus: "00:aa:bb:..."
                hex_part = line.replace(":", "").replace(" ", "")
                n_hex_parts.append(hex_part)

        if line.startswith("publicExponent"):
            # "publicExponent: 65537 (0x10001)"
            parts = line.split()
            # phần tử thứ 1 sau dấu ":" là số thập phân
            e_dec = int(parts[1])

    if not n_hex_parts or e_dec is None:
        raise RuntimeError("Failed to parse modulus or exponent from openssl output")

    n_hex = "".join(n_hex_parts)
    n_int = int(n_hex, 16)
    return n_int, e_dec


def generate_public_key():
    """Tạo public.pem từ private.key."""
    rc, out, err = run_cmd(
        [OPENSSL, "rsa", "-in", PRIVATE_KEY, "-pubout", "-out", PUBLIC_KEY]
    )
    if rc != 0:
        raise RuntimeError(f"openssl rsa -pubout failed: {err.decode()}")


def generate_session_secret_and_cipher():
    """
    Sinh session_secret ngẫu nhiên (32 bytes) và encrypt bằng RSA PKCS#1 v1.5:
      c0 = RSA_encrypt(secret)
    """
    # 32 bytes bí mật
    secret = os.urandom(32)
    Path(SECRET_FILE).write_bytes(secret)

    # Encrypt bằng public.pem
    rc, out, err = run_cmd(
        [OPENSSL, "rsautl", "-encrypt", "-pubin", "-inkey", PUBLIC_KEY, "-pkcs",
         "-in", SECRET_FILE, "-out", CIPHERTEXT_FILE]
    )
    if rc != 0:
        raise RuntimeError(f"openssl rsautl -encrypt failed: {err.decode()}")

    c0_bytes = Path(CIPHERTEXT_FILE).read_bytes()
    return secret, c0_bytes


def handle_client(conn, addr, n, e, c0_bytes):
    print(f"[+] Client connected from {addr}")
    try:
        # Gửi n, e, c0 cho attacker
        conn.sendall(f"MODULUS:{n:x}\n".encode())
        conn.sendall(f"EXPONENT:{e:x}\n".encode())
        conn.sendall(f"CIPHERTEXT:{c0_bytes.hex()}\n".encode())

        # Oracle loop
        while True:
            data = b""
            # đọc 1 dòng hex
            while not data.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk

            if not data:
                break

            hex_str = data.strip().decode(errors="ignore")
            if not hex_str:
                continue

            # convert hex -> bytes
            try:
                c_bytes = bytes.fromhex(hex_str)
            except ValueError:
                # malformed => treat as invalid
                time.sleep(INVALID_DELAY)
                conn.sendall(b"OK\n")
                continue

            # Dùng openssl rsautl -decrypt -pkcs để check padding
            rc, out, err = run_cmd(
                [OPENSSL, "rsautl", "-decrypt", "-inkey", PRIVATE_KEY, "-pkcs"],
                input_bytes=c_bytes,
            )

            valid = (rc == 0)

            if valid:
                # giả lập slow path (derive key, MAC, ...)
                time.sleep(VALID_DELAY)
            else:
                # fast fail
                time.sleep(INVALID_DELAY)

            conn.sendall(b"OK\n")

    except Exception as e:
        print(f"[-] Handler error: {e}")
    finally:
        conn.close()
        print(f"[+] Client disconnected: {addr}")


def main():
    print("[*] Using OpenSSL:", OPENSSL)
    print("[*] Private key:", PRIVATE_KEY)

    # B1. Tạo public key từ private
    generate_public_key()

    # B2. Lấy n, e từ private.key
    n, e = extract_n_e_from_private()
    k = (n.bit_length() + 7) // 8
    print(f"[+] RSA modulus bits: {n.bit_length()}, k={k} bytes")
    print(f"[+] Public exponent e={e}")

    # B3. Sinh session_secret và ciphertext
    secret, c0_bytes = generate_session_secret_and_cipher()
    print(f"[DEBUG] Session secret (hex): {secret.hex()}")
    print(f"[DEBUG] c0 (first 16 hex): {c0_bytes.hex()[:16]}")

    # B4. Lắng nghe socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[+] Oracle server listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            handle_client(conn, addr, n, e, c0_bytes)


if __name__ == "__main__":
    main()
