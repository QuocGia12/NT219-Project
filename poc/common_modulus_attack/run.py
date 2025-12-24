import time
import csv
from gen_rsa_key import gen_common_modulus_rsa
from common_modulus_attack import common_modulus_attack
from math import gcd

N_BITS_LIST = [512, 1024, 2048]

with open("../../logs/common_modulus_attack/results.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "n_bits", "e1", "e2", "gcd_e", "attack_time", "result"
    ])

    for n_bits in N_BITS_LIST:
        for _ in range(10):
            n, e1, e2, c1, c2, m_real = gen_common_modulus_rsa(n_bits)

            start = time.time()
            m_found = common_modulus_attack(n, e1, e2, c1, c2)
            elapsed = time.time() - start
            result = ""
            success = int(m_found == m_real)

            if (success): 
                result = "success"
            else: 
                result = "fail"

            writer.writerow([
                n_bits, e1, e2, gcd(e1, e2),
                round(elapsed, 6), result     
            ])

            print(f"[+] n={n_bits}, success={success}")
