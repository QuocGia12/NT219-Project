#!/usr/bin/env python3
# challenge_singlefile_secure_filled.py

import base64, textwrap, math

_parts_n = ['MTI1NjM0NzIzNjUyMjU3NTY2Mjk3MzQyNTU5NDgwOTM1NDcwNTExOTkwMjA3', 'MTQzNTc3ODE5NTkxOTMyMzYxODUxODI3NDQ1MDIyMDA4ODQ4NzMwNjE4MDc1', 'NjMzMzUzNDIyOTc3Nzk4MjM5MDU2NjY4Njg0NDQ0NDA5MzgwMjk4MzQ0Mjk4', 'Njc1Njg5MTQ0MDQ4MDg1NzEwOTM=']
_parts_e = ['OTQ4NzI4MzQ2NTM3NTc5NTU5NjM3NjkxMTc2NDM2MzgxNTExMjgwMjc2NjIy', 'Mzg4ODU4MTEzNzI1MTI3OTI0OTQ1MjUwMTE3NTc3ODcwMDUwMjM1Mzc4OTcz', 'MTU4Nzk2NjYzOTE2NTE5ODg2NjEzMjc3MzM2NzU4NjM5MzkzMzM4MjUxNTY2', 'MTU0MzE2MjI2MDI3NDA5OTA2Nw==']
_parts_c = ['MzM4MjYxMjE4MzYzNDYxODExODIwMzA2NTIyOTA1NzkzMDUwMzA4Mzk2ODA4', 'MTY0MjgwMjI5NTgxOTU4NTU0ODE2NjgxMjA1NjkyNTE3MDkzNjU4NTEwNzQ1', 'ODEwMjAxNDk1OTczMzg0NDQ5NTYyMzk4OTYwNzIwOTU0NjgwODQ5MjY2Mzc4', 'NDAwNzkyNTk2ODA0MzIwNzE1NA==']


def _join_and_decode_int(parts):
    s = "".join(parts)
    b = base64.b64decode(s)
    try:
        t = b.decode('utf-8')
        if t.isdigit():
            return int(t)
    except Exception:
        pass
    return int.from_bytes(b, 'big')

n = _join_and_decode_int(_parts_n)
e = _join_and_decode_int(_parts_e)
c = _join_and_decode_int(_parts_c)

INFO_TEXT = f"e = {e}\nn = {n}\nc = {c}\n"

MAX_TRIES = 5  # giới hạn số lần submit

def recv_input(prompt="> "):
    try:
        return input(prompt)
    except EOFError:
        return ""

def handle_interactive():
    tries = 0
    
    # Hiển thị thông tin ngay khi chạy
    print("============================")
    print("      A RSA CHALLENGE      ")
    print("============================")
    print(INFO_TEXT)
    print(f"You have {MAX_TRIES} attempts to capture the flag.\n")
    
    while tries < MAX_TRIES:
        cand = recv_input("Enter your flag candidate (e.g. W1n{...}): ").strip()
        
        if cand == "":
            print("No input. Please try again.\n")
            continue  # Không tính attempt nếu input rỗng
            
        tries += 1
        
        try:
            m = int.from_bytes(cand.encode('utf-8'), 'big')
        except Exception:
            print("Cannot convert input to bytes.\n")
            print(f"You have {MAX_TRIES - tries} tries left.\n")
            continue
            
        try:
            c_cand = pow(m, e, n)
        except Exception:
            print("Error during modular exponentiation.\n")
            print(f"You have {MAX_TRIES - tries} tries left.\n")
            continue
            
        if c_cand == c:
            print("\nYour flag: " + cand)
            print("That's right!! Congratulation! You breaked a RSA Challenge!")
            return
        else:
            remaining = MAX_TRIES - tries
            if remaining > 0:
                print(f"Oh no, try again please.")
                print(f"You have {remaining} tries left.\n")
            else:
                print("Too many attempts. Bye.")
                return

if __name__ == "__main__":
    if not (isinstance(n, int) and isinstance(e, int) and isinstance(c, int)):
        print("ERROR: public values not parsed correctly.")
    else:
        handle_interactive()