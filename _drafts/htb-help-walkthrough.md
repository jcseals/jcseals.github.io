---
layout: post
author: jseals
title: "Help: Hack The Box Walk-through"
image: htb-help/help.png
---

## Background

Help is a "vulnerable by design" machine from [hackthebox.eu][1]. In this walk-through I perform the actions of an attacker. The goal is twofold: first get user-level privileges on the box and get the key in /home/$USER/user.txt. Second, escalate privileges to root and get the flag at /root/root.txt.

## Victim Machine Specs
![help.png](/assets/images/posts/htb-help/help.png)

## Reconnaissance

As always, the easiest and most effective tool in the reconnaissance stage is nmap. The nmap flags in the command below will enable TCP SYN/Connect port scanning, OS detection, service version detection, and script scanning.

```text
~/ctf/htb/help λ sudo nmap -sS -A 10.10.10.121
```

```text
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-29 08:41 CDT
Nmap scan report for 10.10.10.121
Host is up (0.051s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e5:bb:4d:9c:de:af:6b:bf:ba:8c:22:7a:d8:d7:43:28 (RSA)
|   256 d5:b0:10:50:74:86:a3:9f:c5:53:6f:3b:4a:24:61:19 (ECDSA)
|_  256 e2:1b:88:d3:76:21:d4:1e:38:15:4a:81:11:b7:99:07 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.70%E=4%D=5/29%OT=22%CT=1%CU=32842%PV=Y%DS=2%DC=T%G=Y%TM=5CEE8C3
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have a few open ports to work with. OpenSSH 7.2p2, an Apache web-server running 2.4.18, and Node.js Express all running on their standard ports. Nmap also tells us the victim machine is running the Ubuntu flavor of Linux.

## Enumeration

I didn't find any exploits for the versions these services are running on, so let's continue with the easy information gathering and goto the website Apache is serving:

![help-0701.png](/assets/images/posts/htb-help/help-0701.png)

Browsing straight to the IP / root web directory we see the default Apache2 page that is served after installation. We again see our victim machine is running Ubuntu, which is useful information for an attacker. However, the default home page doesn't offer any attack vectors, so let's spider the site with gobuster:

```text
~/ctf/htb/help λ gobuster -x php -u http://10.10.10.121 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.121/
[+] Threads      : 10
[+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : php
[+] Timeout      : 10s
=====================================================
2019/05/29 09:18:06 Starting gobuster
=====================================================
/support (Status: 301)
```

The word list we supplied to gobuster immediately gets a hit. We see a support directory on the web-server, let's check it out:

![help-2103.png](/assets/images/posts/htb-help/help-2103.png)

This looks like some sort of support center web app. We see a login form, those are always of interest. We click through the "Knowledgebase" and "News" tabs at the top, but there's nothing there. The "Submit a Ticket" tab looks functional:

![help-3109.png](/assets/images/posts/htb-help/help-3109.png)

Let's see if we can create a ticket. I fill out the mandatory fields and upload a php reverse shell named "shell.php". If it allows php file uploads, and if we can eventually have Apache serve that shell.php file to us, we may be able to gain access onto the machine:

![help-3330.png](/assets/images/posts/htb-help/help-3330.png)

We click submit, but no dice:

![help-3814.png](/assets/images/posts/htb-help/help-3814.png)

Looks like they may have some type of file extension whitelist or blacklist which doesn't allow for php files to be uploaded. To test that theory, we rename the shell.php file to shell.txt and try to upload that when creating the ticket. This works without an error message and it takes us back to the "Submit a Ticket" page.

At this stage we have possible LFI (Local File Inclusion) capabilities as creating a support ticket allows for file uploads. However, it seems like we can't upload the files we'd like to, and more importantly we don't know how or where to access those uploaded files on the victim web-server.

Let's take a step back and do some more research on this HelpDeskZ software. First, let's use searchsploit to see if there are any available exploits for us to leverage:

```text
~/ctf/htb/help λ searchsploit -t helpdeskz
------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                 |  Path
                                                                               | (/usr/share/exploitdb/)
------------------------------------------------------------------------------- ----------------------------------------
HelpDeskZ 1.0.2 - Arbitrary File Upload                                        | exploits/php/webapps/40300.py
HelpDeskZ < 1.0.2 - (Authenticated) SQL Injection / Unauthorized File Download | exploits/php/webapps/41200.py
```

Interesting! While we haven't confirmed our version of HelpDeskZ yet, it's nice to have potential exploits that could help us. We see that exploit 41200 requires one to be authenticated, and since we don't have login credentials yet, let's examine 40300 first. Reading through the exploit, the author tells us that the HelpDeskZ software has a weakness in the file renaming function of the uploaded file when creating a ticket (the same process we tried before). He then references the [HelpDeskZ code repository][2] on github.com.

More good news for us. Not only is this exploit looking incredibly useful to us, but the HelpDeskZ software is open-sourced and available on github. This allows us to look through if needed to find more vulnerabilities.

## Exploitation

## Privilege Escalation

[1]: https://www.hackthebox.eu
[2]: https://github.com/evolutionscript/HelpDeskZ-1.0/blob/master/controllers/submit_ticket_controller.php
[3]: https://site-url