import time, csv
from gen_rsa import gen_instances
from hastad import hastad_attack
from sympy import primerange

N_BITS = 1024
E_LIST = list(primerange(3, 62))  # e thuộc [3, 61]

with open("../../logs/hastad_attack/results.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["e", "k", "n_bits", "attack_time", "success"])

    for e in E_LIST:
        k = e
        m, instances = gen_instances(e, k, N_BITS)
        ns = [n for n, c in instances]
        cs = [c for n, c in instances]

        start = time.time()
        m_found = hastad_attack(ns, cs, e)
        elapsed = time.time() - start

        success = int(m_found == m)
        writer.writerow([e, k, N_BITS, round(elapsed, 6), success])

        print(f"[+] e={e}, success={success}")
