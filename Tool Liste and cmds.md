# Complete Reconnaissance Tool List with Demo & Advanced Commands

## **Network Scanning & Discovery**

### **Nmap**
**Purpose:** Network exploration and security auditing

#### **Basic Commands:**
```bash
# Basic TCP scan
nmap 10.10.10.10

# Service version detection
nmap -sV 10.10.10.10

# Default scripts + version
nmap -sC -sV 10.10.10.10
```

#### **Advanced Commands:**
```bash
# Stealth SYN scan
nmap -sS 10.10.10.10

# Full port scan with timing optimization
nmap -p- --min-rate 10000 10.10.10.10

# UDP top ports scan
nmap -sU --top-ports 100 10.10.10.10

# OS detection + version + scripts
nmap -A 10.10.10.10

# NSE vulnerability scripts
nmap --script vuln 10.10.10.10

# Save output in all formats
nmap -sC -sV -oA full_scan 10.10.10.10

# Firewall evasion with fragmentation
nmap -f 10.10.10.10

# Scan from decoy IPs
nmap -D RND:10 10.10.10.10
```

### **Masscan**
**Purpose:** Ultra-fast port scanner

#### **Basic Commands:**
```bash
# Scan entire subnet for port 80
masscan 10.10.10.0/24 -p80

# Scan multiple ports
masscan 10.10.10.0/24 -p80,443,22,21
```

#### **Advanced Commands:**
```bash
# Fast full port scan
masscan 10.10.10.10 -p0-65535 --rate=10000

# Scan with banner grabbing
masscan 10.10.10.0/24 -p80,443 --banners

# Output to file
masscan 10.10.10.0/24 -p1-65535 -oJ masscan_output.json
```

---

## **Web Application Reconnaissance**

### **Subdomain Enumeration**

#### **Subfinder**
```bash
# Basic subdomain discovery
subfinder -d example.com

# With multiple sources
subfinder -d example.com -s crt,anubis,hackertarget

# Output to file
subfinder -d example.com -o subdomains.txt
```

#### **Amass**
```bash
# Passive enumeration
amass enum -passive -d example.com

# Active enumeration
amass enum -active -d example.com -brute -w wordlist.txt

# Continuous monitoring
amass track -d example.com
```

#### **Assetfinder**
```bash
# Find domains and subdomains
assetfinder example.com

# Include subdomains of subdomains
assetfinder --subs-only example.com
```

### **Directory & File Brute-Forcing**

#### **Gobuster**
```bash
# Directory brute-forcing
gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt

# With extensions
gobuster dir -u http://example.com -w wordlist.txt -x php,html,js,txt

# Virtual host discovery
gobuster vhost -u http://example.com -w subdomains.txt

# DNS subdomain brute-forcing
gobuster dns -d example.com -w subdomains.txt
```

#### **FFUF (Fast Web Fuzzer)**
```bash
# Basic directory fuzzing
ffuf -u http://example.com/FUZZ -w wordlist.txt

# Parameter fuzzing
ffuf -u http://example.com/?param=FUZZ -w params.txt

# Virtual host fuzzing
ffuf -u http://example.com -H "Host: FUZZ.example.com" -w subdomains.txt

# Multi-level fuzzing
ffuf -u http://example.com/FUZZ/SUFFIX -w dirs.txt:FUZZ -w extensions.txt:SUFFIX
```

#### **Dirb**
```bash
# Basic scan
dirb http://example.com

# With custom wordlist
dirb http://example.com /usr/share/wordlists/dirb/big.txt

# With extensions
dirb http://example.com -X .php,.html,.txt
```

### **Web Vulnerability Scanners**

#### **Nikto**
```bash
# Basic web scan
nikto -h http://example.com

# Scan with specific port
nikto -h http://example.com:8080

# Output to file
nikto -h http://example.com -o nikto_scan.html -F html
```

#### **WhatWeb**
```bash
# Basic technology detection
whatweb example.com

# Verbose output
whatweb -v example.com

# Aggressive detection
whatweb -a 3 example.com
```

#### **WPScan** (WordPress)
```bash
# Basic WordPress scan
wpscan --url http://example.com

# Enumerate users
wpscan --url http://example.com --enumerate u

# Password brute force
wpscan --url http://example.com --usernames admin --passwords rockyou.txt
```

---

## **Service-Specific Enumeration**

### **SMB/CIFS**
#### **Smbclient**
```bash
# List shares
smbclient -L //10.10.10.10 -N

# Connect to share
smbclient //10.10.10.10/sharename -N

# Download all files
smbclient //10.10.10.10/sharename -N -c "prompt; recurse; mget *"
```

#### **Enum4linux / Enum4linux-ng**
```bash
# Comprehensive SMB enumeration
enum4linux-ng 10.10.10.10 -A -oA smb_enum

# Basic enumeration
enum4linux -a 10.10.10.10
```

#### **CrackMapExec**
```bash
# SMB share enumeration
crackmapexec smb 10.10.10.10 --shares

# Password spraying
crackmapexec smb 10.10.10.0/24 -u users.txt -p passwords.txt

# Check for eternalblue
crackmapexec smb 10.10.10.0/24 -u '' -p '' -M eternalblue
```

### **SNMP**
#### **Snmpwalk**
```bash
# Basic SNMP walk
snmpwalk -v2c -c public 10.10.10.10

# Get system info
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.1

# Enumerate running processes
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.25.4.2.1.2
```

#### **Onesixtyone**
```bash
# SNMP community string brute force
onesixtyone -c community.txt 10.10.10.10

# Scan multiple hosts
onesixtyone -c community.txt -i hosts.txt
```

### **DNS Enumeration**
#### **Dig**
```bash
# Basic DNS query
dig example.com ANY

# Zone transfer attempt
dig @ns1.example.com example.com AXFR

# Reverse DNS lookup
dig -x 10.10.10.10

# Specific record types
dig example.com MX
dig example.com TXT
```

#### **Dnsrecon**
```bash
# Comprehensive DNS enumeration
dnsrecon -d example.com

# Zone transfer attempt
dnsrecon -d example.com -a

# Brute force subdomains
dnsrecon -d example.com -D wordlist.txt -t brt
```

#### **DNSenum**
```bash
# Full DNS enumeration
dnsenum example.com

# With subdomain brute force
dnsenum --dnsserver 8.8.8.8 --threads 50 -f dns.txt --noreverse example.com
```

---

## **SSL/TLS Analysis**

### **TestSSL.sh**
```bash
# Comprehensive SSL scan
testssl.sh example.com:443

# Check specific vulnerabilities
testssl.sh --heartbleed --poodle --freak example.com
```

### **SSLscan**
```bash
# Basic SSL scan
sslscan example.com

# Check specific cipher suites
sslscan --tlsall example.com:8443
```

### **OpenSSL**
```bash
# Certificate information
openssl s_client -connect example.com:443 -servername example.com < /dev/null

# Check certificate expiry
openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -noout -dates

# Cipher suite enumeration
openssl ciphers -v 'ALL:eNULL' | cut -d' ' -f3
```

---

## **Advanced Reconnaissance Tools**

### **Recon-ng**
**Purpose:** Full-featured web reconnaissance framework

```bash
# Launch recon-ng
recon-ng

# Example workflow:
[recon-ng] > marketplace install all
[recon-ng] > workspaces create example_com
[recon-ng] > use recon/domains-hosts/brute_hosts
[recon-ng] > set source example.com
[recon-ng] > run
```

### **theHarvester**
**Purpose:** Gather emails, subdomains, hosts, etc.

```bash
# Basic reconnaissance
theHarvester -d example.com -b all

# Limit sources
theHarvester -d example.com -b google,bing

# Save results
theHarvester -d example.com -b all -f output.html
```

### **Sublist3r**
```bash
# Basic subdomain enumeration
sublist3r -d example.com

# With specific engines
sublist3r -d example.com -e google,yahoo,bing
```

### **Aquatone**
```bash
# Discover and screenshot websites
echo "example.com" | aquatone

# With port scan
subfinder -d example.com | aquatone -ports 80,443,8080,8443
```

---

## **Network Service Scanners**

### **Netcat (nc)**
```bash
# Basic port scan
nc -zv 10.10.10.10 1-1000

# Banner grabbing
echo "HEAD / HTTP/1.0\n\n" | nc 10.10.10.10 80

# Create reverse shell listener
nc -lvnp 4444
```

### **Netcat (ncat)**
```bash
# Persistent listener with SSL
ncat --ssl -lvnp 443

# Port scan with version detection
ncat -v 10.10.10.10 22
```

---

## **Automated Reconnaissance Scripts**

### **Autorecon**
```bash
# Comprehensive automated reconnaissance
autorecon 10.10.10.10

# Multiple targets
autorecon 10.10.10.0/24

# With specific options
autorecon -t 10.10.10.10 --only-scans-list quick
```

### **Nmap Automator**
```bash
# Full automated scan
nmapAutomator.sh -H 10.10.10.10 -t All

# Network discovery only
nmapAutomator.sh -H 10.10.10.0/24 -t Network
```

### **Osmedeus**
```bash
# Full reconnaissance workflow
osmedeus -t example.com

# With specific workspace
osmedeus -t example.com -w custom_workspace
```

---

## **Advanced Techniques & One-Liners**

### **Complete Reconnaissance Pipeline**
```bash
# Full subdomain enumeration pipeline
subfinder -d example.com -silent | anew subs.txt | httpx -silent | tee alive.txt

# Port scan + service discovery combo
nmap -sC -sV -oA initial_scan 10.10.10.10 && masscan -p1-65535 10.10.10.10 --rate=1000 -oG masscan.out

# Web discovery pipeline
cat alive.txt | waybackurls | tee wayback.txt && cat alive.txt | gau | tee gau.txt
```

### **Quick Recon Script**
```bash
#!/bin/bash
# quick_recon.sh

domain=$1
echo "[+] Starting reconnaissance for: $domain"

# Subdomains
echo "[+] Enumerating subdomains..."
subfinder -d $domain -o subfinder_$domain.txt
amass enum -passive -d $domain -o amass_$domain.txt
cat subfinder_$domain.txt amass_$domain.txt | sort -u > all_subs_$domain.txt

# Alive subdomains
echo "[+] Checking alive subdomains..."
cat all_subs_$domain.txt | httpx -silent > alive_$domain.txt

# Screenshots
echo "[+] Taking screenshots..."
cat alive_$domain.txt | aquatone -out aquatone_$domain

# Directory brute force
echo "[+] Directory brute force..."
parallel -j 5 "gobuster dir -u {} -w /usr/share/wordlists/dirb/common.txt -o gobuster_{/.}.txt" ::: $(cat alive_$domain.txt)

echo "[+] Reconnaissance complete!"
```

### **Advanced Nmap NSE Scripts**
```bash
# SMB enumeration scripts
nmap --script smb-os-discovery,smb-enum-shares,smb-enum-users 10.10.10.10

# HTTP enumeration scripts
nmap --script http-enum,http-headers,http-methods 10.10.10.10

# MySQL enumeration
nmap --script mysql-databases,mysql-users,mysql-variables 10.10.10.10

# All safe scripts
nmap --script "safe" 10.10.10.10
```

---

## **Pro Tips for Effective Reconnaissance**

1. **Always use multiple tools** - Different tools find different things
2. **Save all outputs** - Use `-oA` format in nmap, save to files
3. **Use wordlists effectively** - Combine common wordlists with custom ones
4. **Rate limiting** - Be careful not to overwhelm targets
5. **Automate repetitive tasks** - Create scripts for common reconnaissance workflows
6. **Keep tools updated** - Reconnaissance tools evolve rapidly
7. **Document everything** - Keep detailed notes of what you find

This comprehensive list covers everything from basic reconnaissance to advanced techniques. Start with the basic commands and gradually incorporate the advanced ones as you become more comfortable with the tools.
