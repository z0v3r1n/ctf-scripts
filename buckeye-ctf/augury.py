#!/usr/bin/env python3
from pwn import *
from pathlib import Path

def gen(x): return (x*3404970675+3553295105)&0xFFFFFFFF

io=remote("augury.challs.pwnoh.io", 1337, ssl=True)

io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"> ", b"known_file")
io.sendlineafter(b"> ", b"password123!")
io.sendlineafter(b"> ", b"89504E470D0A1A0A"+b"00"*0x100)

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"> ", b"known_file")
dummy = io.recvline().strip()

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"> ", b"secret_pic.png")
hexdata = io.recvline().strip().decode()

c=bytes.fromhex(hexdata)
png=b"\x89PNG\r\n\x1a\n"
k=int.from_bytes(c[:4],"big")^int.from_bytes(png[:4],"big")
out=bytearray(len(c));i=0;ks=k

while i<len(c):
    key=ks.to_bytes(4,"big")
    for j in range(4):
        if i+j>=len(c): break
        out[i+j]=c[i+j]^key[j]
    ks=gen(ks);i+=4

Path("secret_pic.png").write_bytes(out)
