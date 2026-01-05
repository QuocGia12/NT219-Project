# oracle.py
import socket
import time
import statistics
import binascii
import config

class TimeOracle:
    def __init__(self):
        self.host = config.HOST
        self.port = config.PORT
        self.socket = None
        self.n = None
        self.e = None
        self.k = None
        self.c0 = None # Target ciphertext
        self.threshold = None # Ngưỡng thời gian phân loại
        self.query_count = 0

    def connect(self):
        """Kết nối và nhận Header (N, E, C0) từ Server"""
        print(f"[*] Connecting to {self.host}:{self.port}...")
        self.socket = socket.create_connection((self.host, self.port), timeout=config.TIMEOUT)
        
        # Helper đọc line
        def _read_line():
            data = b""
            while not data.endswith(b"\n"):
                chunk = self.socket.recv(1)
                if not chunk: break
                data += chunk
            return data.decode().strip()

        # Parse Header
        mod_line = _read_line()
        exp_line = _read_line()
        cip_line = _read_line()

        self.n = int(mod_line.split(":")[1], 16)
        self.e = int(exp_line.split(":")[1], 16)
        self.c0 = int(cip_line.split(":")[1], 16)
        self.k = (self.n.bit_length() + 7) // 8

        print(f"[+] Connected. Modulus size: {self.n.bit_length()} bits")
        print(f"[+] Target Ciphertext: {hex(self.c0)[:30]}...")

    def _measure_rtt(self, c_int):
        """Gửi 1 request và đo Round-Trip Time"""
        c_bytes = c_int.to_bytes(self.k, "big")
        c_hex = binascii.hexlify(c_bytes).decode()
        msg = (c_hex + "\n").encode()

        start = time.perf_counter()
        self.socket.sendall(msg)
        
        # Đọc phản hồi "OK\n"
        data = b""
        while not data.endswith(b"\n"):
            chunk = self.socket.recv(16)
            if not chunk: break
            data += chunk
        
        end = time.perf_counter()
        return end - start

    def calibrate(self):
        """
        Đo mẫu Valid vs Invalid để tìm ngưỡng (Threshold).
        """
        print("[*] Calibrating Oracle (measuring network & CPU jitter)...")
        
        # 1. Đo Valid (Gửi lại chính c0 - chắc chắn đúng padding)
        # Server sẽ chạy BigNum loop -> Chậm
        valid_times = [self._measure_rtt(self.c0) for _ in range(config.SAMPLES_CALIB)]
        median_valid = statistics.median(valid_times)

        # 2. Đo Invalid (XOR c0 để phá cấu trúc padding)
        # Server sẽ thoát sớm -> Nhanh
        c_invalid = self.c0 ^ 0xFF
        invalid_times = [self._measure_rtt(c_invalid) for _ in range(config.SAMPLES_CALIB)]
        median_invalid = statistics.median(invalid_times)

        # 3. Tính Threshold
        self.threshold = (median_valid + median_invalid) / 2
        gap = median_valid - median_invalid

        print(f"    Median Valid:   {median_valid*1000:.4f} ms")
        print(f"    Median Invalid: {median_invalid*1000:.4f} ms")
        print(f"    Gap: {gap*1000:.4f} ms")
        print(f"[+] Calibration Done. Threshold: {self.threshold*1000:.4f} ms")

        valid_times = [self._measure_rtt(self.c0) for _ in range(config.SAMPLES_CALIB)]
        invalid_times = [self._measure_rtt(c_invalid) for _ in range(config.SAMPLES_CALIB)]
        
        if gap < 0.005: # Warning nếu gap quá nhỏ (< 5ms)
            print("[!] WARNING: Time gap is very small. Network jitter might fail the attack.")

        return valid_times, invalid_times, median_valid, median_invalid

    def query(self, c_int):
        """
        Hàm cốt lõi: Trả về True nếu Padding Correct (Chậm hơn Threshold)
        """
        self.query_count += 1
        samples = [self._measure_rtt(c_int) for _ in range(config.SAMPLES_PER_QUERY)]
        median_rtt = statistics.median(samples)
        
        # Nếu thời gian > ngưỡng => Valid (True)
        return median_rtt > self.threshold

    def close(self):
        if self.socket: self.socket.close()