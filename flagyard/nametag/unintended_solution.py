#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './nametag')
libc = ELF(exe.libc.path)

def add(idx):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b": ", str(idx).encode())

def show(idx):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b": ", str(idx).encode())
    io.recvuntil(b"Name: ")
    return io.recvline().strip()

io = process(exe.path)

add(0)
print(show(0).decode())
