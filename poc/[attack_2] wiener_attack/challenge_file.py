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

MENU = textwrap.dedent("""\
============================
      RSA CHALLENGE 2
============================
Choose an option:
1. Get infomation
2. Get a hint
3. Capture the Flag
0. I'm lose
""")

HINT_MENU = textwrap.dedent("""\
What's hint do you want? (Choose 1/2/3)
""")

INFO_TEXT = f"e = {e}\nn = {n}\nc = {c}\n"

MAX_TRIES = 5  # gioi han so lan submit (de tranh bruteforce)

def recv_input(prompt="> "):
    try:
        return input(prompt)
    except EOFError:
        return ""

def handle_interactive():
    tries = 0
    while True:
        print(MENU)
        choice = recv_input("Your choice: ").strip()
        if choice == "0" or choice.lower() == "q" or choice.lower() == "quit":
            print("You are loser, baby. See you again!")
            return
        elif choice == "1":
            print(INFO_TEXT)
            continue
        elif choice == "2":
            print(HINT_MENU)
            h = recv_input("Which hint: ").strip()
            if h == "1":
                print("Hint 1: What if d is too small?\n")
            elif h == "2":
                print("Hint 2: Did you hear about Wiener?\n")
            elif h == "3":
                print("Hint 3: The flag is a string, not long><\n")
            else:
                print("Invalid hint choice.")
            continue
        elif choice == "3":
            if tries >= MAX_TRIES:
                print("Too many attempts. Bye.")
                return
            cand = recv_input("Enter your flag candidate (e.g. W1n{...}): ").strip()
            if cand == "":
                print("No input. Return to menu.")
                continue
            tries += 1
            try:
                m = int.from_bytes(cand.encode('utf-8'), 'big')
            except Exception:
                print("Cannot convert input to bytes.")
                continue
            try:
                c_cand = pow(m, e, n)
            except Exception:
                print("Error during modular exponentiation.")
                continue
            if c_cand == c:
                print("\nYour flag: " + cand)
                print("That's right!! Congratulation! You breaked a RSA Challenge!")
                return
            else:
                print("Oh no, try again please.")
                print(f"Hint: you have {MAX_TRIES - tries} tries left.\n")
                continue
        else:
            print("Invalid choice. Try again.\n")
            continue

if __name__ == "__main__":
    if not (isinstance(n, int) and isinstance(e, int) and isinstance(c, int)):
        print("ERROR: public values not parsed correctly.")
    else:
        handle_interactive()
