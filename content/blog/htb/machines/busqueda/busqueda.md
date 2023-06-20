---
title: "HTB - Busqueda"
date: 2023-06-08T10:51:02+09:30
draft: false
---

[//]: # (Project: HTB Machine Writeups - Generated with Python3)  
[//]: # (Title: HTB Busqueda Writeup)  
[//]: # (Author: M4773L)  
[//]: # (Date: 23/05/2023 - 12:33 PM)  
[//]: # (Date_Modified: ) 
[//]: # (WEBSITE_URL: http://m4773l.github.io)
[//]: # (GITHUB_REPO_URL: https://github.com/M4773L)

# Busqueda
**10.10.11.208**  
Busqeuda is an easy rated machine on the HackTheBox platform. The machine hosts a simple Flask application which handles user supplied input with an unsafe function which leads to remote code execution. 
Privilege escalation is relatively straightforward involving checking repository configuration, password reusage and levereging commands that we can run as 'sudo'.  
<!--more-->  

![Machine Info Card](/blog/htb/machines/busqueda/img/busqueda.png)  
&nbsp;  

## Enumeration  
#### Nmap  
![Nmap Aggressive Scan](/blog/htb/machines/busqueda/img/nmap_aggressive.jpg)  
A quick and noisy Aggressive scan in Nmap will identify open TCP ports and run the default Nmap scripts against the services listening on the identified ports.  

![Nmap Full TCP](/blog/htb/machines/busqueda/img/nmap_fulltcp.jpg)  
A full TCP scan will identify anything that was not covered in the previous 'agressive' scan, today I am using a connect scan with service / version identification across the whole port range. ```-sTV -p-```   

![Nmap Top 1000 UDP](/blog/htb/machines/busqueda/img/nmap_topudp.jpg)  
A scan of the top 1000 UDP ports will hopefully identify any services listening on a UDP port.  

**Add Target to Hosts File**  
![Vim Hosts](/blog/htb/machines/busqueda/img/vim_hosts.jpg)  
Add the site URL we identified in the 'aggressive' Nmap scan to your hosts file using your text editor of choice.  

![Hosts](/blog/htb/machines/busqueda/img/hosts_file_1.jpg)  

#### Directory Fuzzing
![Directory Fuzz](/blog/htb/machines/busqueda/img/dir_fuzz.jpg)  
Using FFUF I will attempt to find directories that are being served on the target which may not be linked from the site.  

#### Searchor
![Burp Scope](/blog/htb/machines/busqueda/img/burp_scope.jpg)  
Fire up Burpsuite and add the target sites URL to the scope, this allows us to proxy requests and intercept for modification if required.  

![Firefox Homepage](/blog/htb/machines/busqueda/img/homepage_1.jpg)  
![Firefox Homepage 2](/blog/htb/machines/busqueda/img/homepage_2.jpg)  
Navigating to the 'http://searcher.htb/' in Firefox and we are greeted with a search engine named 'Searchor'. The application allows users to perform searches from several platforms and providers from a single user interface.  

```Powered by Flask and Searchor 2.4.0```  
The app is written in Python, using the Flask web-framework and the version of 'Searchor' is '2.4.0'.  
&nbsp;  

## Foothold
Using your search engine of choice identify any disclosed vulnerabilites for 'Searchor 2.4.0'.  

![Snyk Searchor Vulnerabilities](/blog/htb/machines/busqueda/img/snyk_searchor.jpg)  
From the search results I have navigated to the Snyk Vulnerability database. You can see there is an arbitrary code execution vulnerability due to an 'unsafe implementation of eval method'. This sounds great, lets dig a little deeper.  
[Snyk Searchor Vulnerabilities](https://security.snyk.io/vuln/SNYK-PYTHON-SEARCHOR-3166303)  

![GitHub Exploit POC](/blog/htb/machines/busqueda/img/github_poc_2.jpg)  
Also from the search engine results I was able to find a proof-of-concept exploit for the vulnerability on GitHub.  
[Searchor 2.4.2 Exploit POC (GitHub)](https://github.com/jonnyzar/POC-Searchor-2.4.2)  

#### Explanation
The vulnerability in the Searchor application rests in this single line of code from the search function. There is no sanitation or conditional checks performed on the user supplied data which allows the supplied input to be evaluated when received by the 'eval' function. 
This means we can supply our own python3 statements and syntax to execute arbitrary code.  

```
 url = eval(
            f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
        )
```
The 'eval' function in Python will evaluate the supplied expression and if it is a valid Python statement, it will be executed. 
This maps to common weakness enumeration (CWE) 94, improper control of generation of code. 

**For More Information**  
[CWE-94](https://cwe.mitre.org/data/definitions/94.html)  
[Python Eval Function](https://realpython.com/python-eval-function/)  

#### Plan
1. Start a Netcat Listener to recieve the connection from the reverse shell.  
2. Perform a search with the request proxied through Burpsuite.  
3. Modify the payload to include the reverse shell that will be run when handled by the ```eval()``` function.  
4. Recieve connection on listener from reverse shell.  

#### Exploitation
![Netcat Listener](/blog/htb/machines/busqueda/img/nc_listener.jpg)  
Start a Netcat listener on the port of your choice.  

![Intercept Request](/blog/htb/machines/busqueda/img/burp_modifypayload.jpg)  
Over in Burpsuite under the Proxy tab, turn on the 'intercept'. Perform a search from the App in your Browser, I simply left the query parameter empty. Back in Burpsuite, paste your python3 reverse shell payload as the supplied value for the 'query' parameter and forward the request to the target.  

![Reverse Shell](/blog/htb/machines/busqueda/img/reverse_shell.jpg)  
Back at our Netcat listener we have received a connection from the target, the reverse shell has spawned as user 'svc' and we are in the Searchor applications directory at '/var/www/app'.  

&nbsp;  

## Privilege Escalation - User
![Git Config](/blog/htb/machines/busqueda/img/git_config.jpg)  
Listing out the the contents of our current directory and there is a '.git' repository present, lets take a look at the config file. Lucky for us there are hardcoded username and password in the URL to the remote repository.  

![SSH Password Reusage](/blog/htb/machines/busqueda/img/ssh_1.jpg)  
![SSH](/blog/htb/machines/busqueda/img/ssh_2.jpg)  
Checking if the password has been reused proves fruitful when we are able to SSH into the target as user 'svc', from here you can read the user flag.  
&nbsp;  

## Privilege Escalation - Root
![Sudo List](/blog/htb/machines/busqueda/img/sudo_list.jpg)  
Taking a look if we can run any commands as 'sudo' and there is a Python script we can execute. We are currently unable to view the contents of the 'system-checkup.py' file due to requiring root permissions. For now we will see what we can identify by running the script.  

![System-Checkup](/blog/htb/machines/busqueda/img/system_checkup_1.jpg)  
Running the script with the 'docker-ps' argument we can see there are 2 docker containers running on the target, the Searchor application and a Gitea instance. Running the script again this time with the 'docker-inspect' argument we can retrieve the configuration in a JSON format for the Gitea container. Repeat the last command again to retrieve the configuration for the Searchor container.  

[Docker Inspect Documentation](https://docs.docker.com/engine/reference/commandline/inspect/#get-a-subsection-in-json-format)  

**Passowrds from 'docker-inspect'**  
```
"GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh"
"MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh"
```
We identified 2 passwords from the container configuration, to proceed I will take a look at the Gitea instance to see if there is any useful information.  

**Add Target to Hosts File**  
![Vim Hosts](/blog/htb/machines/busqueda/img/vim_hosts.jpg)  
Once again open your 'hosts' file with your text editor of choice.  

![Hosts](/blog/htb/machines/busqueda/img/hosts_file_2.jpg)  
Add the gitea subdomain to the existing line for the 'searcher.htb' target.  

#### Gitea
![Gitea Login](/blog/htb/machines/busqueda/img/gitea_login.jpg)  
After trying a few username/password cominbations 'Administrator' and the database password work and we are able log in.  

![Gitea as Administrator](/blog/htb/machines/busqueda/img/gitea_admin.jpg)  
You can see after logging in we are redirected to the dashboard for the administrator user.  

![System-Checkup File 1](/blog/htb/machines/busqueda/img/gitea_systemcheckup_1.jpg)  
![System-Checkup File 2](/blog/htb/machines/busqueda/img/gitea_systemcheckup_2.jpg)  
Taking a look at the 'system-checkup.py' file we can see that on line 47 the script will call a file named 'full-checkup.sh' from the directory where the python script is executed.   

#### Plan
1. Create a malicous 'full-checkup.sh' file that contains a reverse shell.  
2. Host locally with a Python3 Simple HTTP Server.  
3. Retrieve file from HTTP server using Wget on the target.  
4. Start a Netcat Listener for the reverse shell to connect to.  
5. Make the file executable on target.  
6. Run the system-checkup command we are allowed to run as 'sudo'.  

#### Execution
![Malicious Fullcheckup File](/blog/htb/machines/busqueda/img/full_checkup_reverse_shell.jpg)  
Here is the 'full-checkup.sh' file I have created containing a Python reverse shell, note the shebang line denoting that the file contents are actually to be executed by python3.  

![Python3 HTTP Server](/blog/htb/machines/busqueda/img/python_httpserver.jpg)  
Host your malicous file with a Python3 Simple HTTP Server.  

![Wget File](/blog/htb/machines/busqueda/img/wget_fullcheckup.jpg)  
Transfer the malicous 'full-checkup.sh' file to the target using Wget and change the file mode to executable.  

![Netcat Listener](/blog/htb/machines/busqueda/img/nc_listener_2.jpg)  
Start a Netcat listener to receive the connection from the reverse shell.  

![Run Script](/blog/htb/machines/busqueda/img/sudo_script.jpg)  
Run the 'system-checkup.py' file as root using 'sudo' with 'full-checkup' as the supplied argument. The script will hang as the reverse shell is executed.  

&nbsp;  

## Root
![Reverse Shell as Root](/blog/htb/machines/busqueda/img/root.jpg)
Back at our Netcat listener we receive a connection from the target with a reverse shell as user 'root'. From here you can navigate to the root directory and retrieve the root flag.  

![Shadow File](/blog/htb/machines/busqueda/img/rooted.jpg)  
Here is a snipped version of the shadow file containing the root users password hash.  
&nbsp;  

Note: Next writeup I will use code blocks for terminal output instead of images, it looks cleaner.  
&nbsp;  
 
