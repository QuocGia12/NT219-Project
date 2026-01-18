import time
import csv
from gen_rsa_key import gen_weak_rsa
from wiener import wiener_attack

N_BITS_LIST = [512, 768, 1024, 1280, 1536, 1792, 2048]
D_BITS_LIST = [64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 480, 512, 544]

with open("../../logs/wiener-attack/results.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["n_bits", "d_bits", "ratio", "attack_time", "result"])

    for n_bits in N_BITS_LIST:
        for d_bits in D_BITS_LIST:
            n, e, d_real = gen_weak_rsa(n_bits, d_bits)

            start = time.time()
            d_found = wiener_attack(e, n)
            elapsed = time.time() - start

            success = (d_found == d_real)

            result = ""
            if (success): 
                result = "success"
            else: 
                result = "fail"
            
            ratio = d_bits / n_bits

            writer.writerow([
                n_bits,
                d_bits,
                ratio,
                round(elapsed, 6),
                result
            ])

            print(f"[+] n={n_bits}, d={d_bits}, result={result}")
