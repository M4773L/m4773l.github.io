---
title: "Writeup Generator"
date: 2023-05-23T12:17:37+09:30
draft: false
---

### HackTheBox Writeup Generator
I have been using the HackTheBox platform for a couple of years now and have either been recording my findings in text files or markdown documents. 
To help in keeping the writeups I create the same layout and style, I have created a short Python3 application to create an individualised markdown document 
from a template.  

<!--more--> 

![HTB Writeup Generator](/blog/python/htb_writeup_generator/img/htb_writeup_gen.png)

### How it works
The application follows the folling method:

1. Receive the target machines name, IP address & information card (Downloaded from the target machines page on HTB.) as command line arguments.  
2. Create a directory structure with the root as the machine name, an image sub-directory and copy the card file from the supplied location to the image directory.
If an ```--output``` is supplied as an argument, the directory structure will be created at the supplied location.  
3. Read the template file into a python list.
4. Iterate through the list looking for string matches for cusomisable parameters including; machine name, IP address, info card location and date/time stamp.
When a match is found, the application calls the string replace function to replace the parameter with the user supplied argument.    
5. Write the list back into a new markdown file named as the machine name.  
&nbsp;  

This simple application does exactly what I want by creating a markdown document for a HTB machine writeup from a template file.  
Feel free to check it out here: [**Github Repository**](https://github.com/m4773l/)

