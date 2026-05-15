import base64
import os
import secrets
import string
import subprocess
import sys

FLAG = "HTB{f4K3_fLaG_f0R_t3sT1nG!}"
PASSWORD_FILE = "password"
MAX_MEM = 0x1000
TIMEOUT = 15
PWD_CHARSET = string.ascii_letters + string.digits
PWD_LENGTH = 32
ITERATIONS = 32

def spawn(user=None):
    p = subprocess.Popen([
        "./blinded",
        str(MAX_MEM)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        user=user,
        group=user
    )
    while p.stdout.read(1) != b"\n":
        pass
    return p

def get_proc_maps():
    p = spawn()
    with open(f"/proc/{p.pid}/maps", "r") as f:
        print(f.read())
    p.kill()

def run(payload, user=None):
    p = spawn(user=user)
    try:
        out, err = p.communicate(payload, TIMEOUT)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
    return out, err

def test_payload(payload):
    for i in range(ITERATIONS):
        password = "".join([secrets.choice(PWD_CHARSET) for _ in range(PWD_LENGTH)])
        with open(PASSWORD_FILE, "w+") as f:
            f.write(password)
        os.chmod(PASSWORD_FILE, int("0644", 8))
        out, err = run(payload, user="ctf")
        if out.strip() != password.encode():
            return i, out, err
    else:
        return True

while True:
    print("1. See the light")
    print("2. Get a glimpse of it")
    print("3. Remain in darkness")
    choice = 0
    while choice not in (1, 2, 3):
        try:
            choice = int(input("> "))
        except ValueError:
            continue
    if choice == 1:
        length = int(input("Enter length of payload: "))
        print("Enter payload (base64 encoded): ", end="", flush=True)
        b64 = b""
        while len(b64) < length:
            b64 += sys.stdin.buffer.read(length - len(b64))
        out = test_payload(base64.b64decode(b64))
        if out == True:
            print(FLAG)
            exit()
        else:
            i, out, err = out
            print(f"Exploit failed at i={i}")
            print(f"STDOUT: {out}")
            print(f"STDERR: {err}")
    elif choice == 2:
        get_proc_maps()
    else:
        exit()