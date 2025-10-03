from pwn import *
p = remote('0.cloud.chals.io', 33121)

for _ in range(19):
  p.sendlineafter(b"> ", b"protect FLAG")

p.sendlineafter(b"> ", b"print FLAG=")
p.recvuntil(b"FLAG=")
log.success(''.join(chr((ord(c)+9)%256) for c in p.recvline().strip().decode()))
