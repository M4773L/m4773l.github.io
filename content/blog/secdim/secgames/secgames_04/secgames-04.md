---
title: "Secgames 04"
date: 2023-03-26T09:34:12+09:30
draft: false
---

# SecDim - Secret Leak Challenge
Secrets such as an API or encryption key are used for various security operations. Disclosure of the secret can severely undermine the security of the app. When a secret is mistakenly disclosed, it is not trivial to remove. This challenge examine key activities that must be performed to handled a leaked/disclosed secret.  
- From the challenge on SecDim  
&nbsp;
<!--more-->

## Challenge Overview
After cloning the challenge repository we can proceed to build and run the Dockerised challenge.  
&nbsp;

#### Testing
Navigating to the WebApp in Firefox we are greeted with the following message:  
![Home](/blog/secdim/secgames/secgames_04/img/1_Webapp_Home.png)  
Copy the supplied URL resource and parameter in the message and paste it in the address bar.  
&nbsp;

![Alice Login](/blog/secdim/secgames/secgames_04/img/1_Webapp_Alice.png)  
We are logged in as Alice.  
&nbsp;

![Check Headers](/blog/secdim/secgames/secgames_04/img/1_Webapp_Alice_Headers.png)  
Taking a look at the headers we received in the response, there is a JSON Web Token (JWT) present as the value of the 'authorization' header.  
&nbsp;

#### Code Review
Looking at the applications files in an IDE.  
![Secret Key in App Code](/blog/secdim/secgames/secgames_04/img/2_Exposed_Secret.png)  
We can see the applications secret key is stored as a variable named 'secret'. The Index function upon receiving a GET request will check the headers for an 'authorization' key / value pair, if present the function will verify the token is valid and return a response stating ```Logged in as <username>```. If no 'authorization' header is present the application will respond with ```Login: /login?username=Alice```.  

![Login Function](/blog/secdim/secgames/secgames_04/img/2_Login_Function.png)  
The login function which will sign a JSON web token when supplied a username.  
&nbsp;

#### Assessment
From what we have reviewed soo far, there is a login function that accepts a user supplied username as a URL parameter and will sign a JWT and include it as a header in the response.   
* If no username is supplied the application will respond with a status code 400 (Bad Request) and an error message stating 'username is not provided'. 
* If a username is supplied the application will create a JWT and sign it using the 'secret' key stored in the code. The function then sets the header 'authorization' with the value as the JWT before sending the response to the user.
&nbsp;

#### Vulnerability
CWE-321 - Use of Hardcoded Cryptographic Key  
```"The use of a hard-coded cryptographic key significantly increases the possibility that encrypted data may be recovered."``` - https://cwe.mitre.org/data/definitions/321.html  

With the JWT secret key being stored in the applications code before being pushed to a remote repository, the secret key has potentially been exposed to an unauthorized actor.
&nbsp;

## Knowledge Refresher
Before we proceed we need to understand the fundamentals of Git and what happens when we accidentally include sensitive information in a Git repository.
&nbsp;

#### What is Git
Git is a distributed version control system which tracks changes made to files stored in a repository. Rather than listing changes, Git views the changes as a 'snapshot' of a miniture file system allowing for easy viewing of differences between the various commits.  

* Tracks changes made to files.
* Once cloned, most operations are able to be performed locally.
* When a 'commit' is performed, a 'snapshot' of the repository is added to the  internal database and the branch pointer is moved upto the new commit.  
&nbsp;

#### How does Git handle a previous commit
When we push a new commit to a Git repoository, the old commit(s) remains intact and can be accessed locally using the ```git checkout``` command. Using a tool such as Git Extractor, you can extract the contents of all the previous commits within the repository. 
https://github.com/internetwache/GitTools/tree/master/Extractor

![Previous Commits](/blog/secdim/secgames/secgames_04/img/3_Git_Log.png)
Using the ```git log``` command lets take a look at the commit history for the challenge repository.  

![Secret Key Previous Commits](/blog/secdim/secgames/secgames_04/img/3_Git_Log_Secret_a.png)
....SNIP....
![Secret Key Previous Commits](/blog/secdim/secgames/secgames_04/img/3_Git_Log_Secret_b.png)
Searching for the secret key in previous commits, you can see that in every commit the JWT secret key is present.
Breaking down the command:
* ```git log``` - Used to list and filter a Git repository.
* ```-p``` - Generate patch text for the result.
*  ```-S "<JWT SECRET>"``` - Specifies we are searching for a string folowed by the string we are searching for. 
&nbsp;

## Solution
Now that we have a grasp on what has occured with our JWT secret key and the Git repository, we can proceed to work on our fix for this security vulnerability.  
&nbsp;

Best practice dictates that when we are required to store a secret key we should use environment variables rather than in the applications code.  
&nbsp;

#### Application
Lets copy & remove the harcoded credential from the file named 'Contollers.ts'.  
![Remove Secret Key](/blog/secdim/secgames/secgames_04/img/4_Removed_Secret.png)
JWT secret is removed from line 8 and is instead the variable will load the key from an environment variable in the Docker container named 'SECRET'.

![Dockerfile Enviroment Variable](/blog/secdim/secgames/secgames_04/img/4_Dockerfile_Secret.png)
In the Dockerfile we will export the JWT secret as an environment variable. Note: Do not include the secret key in there as we will still have the same security issue with it being exposed.  
&nbsp;

#### Git Filter Repo
![Git Filter Repo File of strings to replace](/blog/secdim/secgames/secgames_04/img/5_Text_To_Replace.png)
To use Git-filter-repo to replace a string we are required to create an expression that will be searched for in the repository, if found it will be replaced. The expression is made up of 3 components:
* ```literal``` - Specifies that we want to match literal text.
* ```<StringToReplace>``` - The string to be matched which in our case is the JWT secret.
* ```==>``` - Specifies the end of the line.  


![Git Filter Repo Replace text](/blog/secdim/secgames/secgames_04/img/5_Git_Filter_Repo.png)
Using git-filter-repo we can search for and replace the expression contained in the file we just created. Notice the first attempt at filtering failed due to the repository not appearing to be a 'fresh clone', this is due to changes we have made to the 2 files in our IDE. In the second attempt we use the ```--force``` flag to force git-filter-repo to replace the string in the Git repository. 
&nbsp;

#### Verify JWT Secret Key is Gone
![Verify Key has been removed](/blog/secdim/secgames/secgames_04/img/6_Git_Log_Verify.png)
Just to confirm the secret has been removed completely from the challenge repository lets search for the JWT secret once again.  
&nbsp;

#### Note
In a real world scenario, the JWT secret must be revoked due to possibility it has already been compromised. There is also the possibility the remote repository has been cloned, cached or archived elsewhere on the internet.  

```"GitGuardian scanned 1.027 billion new GitHub commits in 2022 (+20% compared to 2021) and found 10,000,000 secrets occurrences (+67% compared to 2022). What is interesting beyond this ever-increasing number is that 1 code author out of 10 exposed a secret in 2022."``` - https://www.helpnetsecurity.com/2023/03/09/github-secrets-exposed/  
&nbsp;

#### Add Origin & Push
![Add Remote Origin](/blog/secdim/secgames/secgames_04/img/7_Add_Remote.png)
Add the remote origin of the challenge repository.  

![Push](/blog/secdim/secgames/secgames_04/img/7_Push.png)
Push your changes to the remote repository, using the ```--force``` flag to force the operation to proceed.  
&nbsp;

#### Challenge Result
![Test Passed](/blog/secdim/secgames/secgames_04/img/8_Test_Passed.png)
Back over on the SecDim challeng page we can see that the various tests have been passed and we have successfully removed the JWT signing secret from the repository.  
&nbsp;

## Cleanup
![Shred / Remove History](/blog/secdim/secgames/secgames_04/img/9_Cleanup.png)
Be sure to remove the file containing the expression we used in Git-filter-repo and clear your command history.  
&nbsp;

Note to self - A slideshow probably would have been more appropriate!
