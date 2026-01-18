# algorithm.py
import utils

class BleichenbacherAlgo:
    def __init__(self, oracle):
        self.oracle = oracle
        self.n = oracle.n
        self.e = oracle.e
        self.B = 2 ** (8 * (oracle.k - 2)) # PKCS#1 const B = 2^(8*(k-2))
    
    def run(self):
        c0 = self.oracle.c0
        B = self.B
        B2 = 2 * B
        B3 = 3 * B
        
        # Khởi tạo khoảng M = {[2B, 3B-1]}
        M = {(B2, B3 - 1)}

        print("[*] Starting Bleichenbacher Algorithm...")

        # --- Step 1: Blinding (Tìm s0) ---
        print("[*] Step 1: Finding s0...")
        s = utils.ceil(self.n, B3)
        while True:
            # c' = c0 * s^e mod n
            c_prime = (c0 * pow(s, self.e, self.n)) % self.n
            if self.oracle.query(c_prime):
                print(f"[+] Found s0: {s}")
                break
            s += 1

        # --- Main Loop (Step 2 & 3) ---
        i = 1
        while True:
            # --- Step 2: Update M (Interval Narrowing) ---
            M_new = set()
            for (a, b) in M:
                r_min = utils.ceil(a * s - B3 + 1, self.n)
                r_max = utils.floor(b * s - B2, self.n)
                
                for r in range(r_min, r_max + 1):
                    low = max(a, utils.ceil(B2 + r * self.n, s))
                    high = min(b, utils.floor(B3 - 1 + r * self.n, s))
                    if low <= high:
                        M_new.add((low, high))
            
            M = M_new
            
            # Kiểm tra kết thúc: Nếu chỉ còn 1 khoảng và a == b
            if len(M) == 1:
                a, b = next(iter(M))
                if a == b:
                    return a # Found m!
            
            if not M:
                return None # Error

            if i % 20 == 0:
                print(f"  [Iter {i}] Intervals count: {len(M)}")

            # --- Step 3: Find next s ---
            s_prev = s
            if len(M) > 1:
                # Case 2a: Nhiều khoảng -> Tăng s chậm
                s = s_prev + 1
                while True:
                    c_prime = (c0 * pow(s, self.e, self.n)) % self.n
                    if self.oracle.query(c_prime):
                        break
                    s += 1
            else:
                # Case 2b: 1 khoảng -> Nhảy s nhanh (Binary Search like)
                a, b = next(iter(M))
                r = utils.ceil(2 * (b * s_prev - 2 * B), self.n)
                found = False
                while not found:
                    s_min = utils.ceil(2 * B + r * self.n, b)
                    s_max = utils.floor(3 * B + r * self.n, a)
                    
                    for s_candidate in range(s_min, s_max + 1):
                        c_prime = (c0 * pow(s_candidate, self.e, self.n)) % self.n
                        if self.oracle.query(c_prime):
                            s = s_candidate
                            found = True
                            break
                    r += 1
            i += 1