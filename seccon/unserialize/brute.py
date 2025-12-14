#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall')

for i in range(1, 256):
    gdbscript = f'''
b *0x401b68
commands
    silent
    if ((($rbp - 0x60) - $rdx) + 1) == *(long*)($rbp - 0x38)
        shell echo {i} > .found
    quit
    end
end
c
'''
    io = process('./chall', aslr=False)
    gdb.attach(io, gdbscript=gdbscript)
    io.sendline(f"0{i:03d}:".encode())
