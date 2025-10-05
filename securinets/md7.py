#!/usr/bin/env python3
from pwn import *

r = remote('numbers.p2.securinets.tn', 7011)
base = "16512691259125612571258125912551254125312521251125012491248124712461245124412431242124112401239123812371236123512341233123212311230122912281227122612251224122312221221122012191218121712161215121412131212121112101209120812071206120512041203120212011200"
    
for i in range(100):
	first_num = str(i) + base + "0"
	second_num = str(i) + base + "00"

	r.sendlineafter(b"first number: ", first_num.encode())
	r.sendlineafter(b"second number: ", second_num.encode())

r.recvuntil(b"flag\n\n")
print(str(r.recvline().strip().decode()))
