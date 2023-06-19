---
title: "Coloured Logs in Python3"
date: 2023-06-19T09:43:18+09:30
draft: false
---

### Python3 - Coloured Logging
I am currently developing an application to enumerate subdomains for Bug Bounty research. For this project I have decided that rather than use plain logging messages, I would like to implement coloured logging to either file, terminal window or both. 
In this post I will walk through a relatively simple method of implementing coloured logging into your Python3 applications.  
<!--more-->  
&nbsp;  

### Example Operation
I have created a short script to demonstrate an easy method of incorporating colour into your applications logging. The script will accept various command line arguments to control whether the logging will be printed to the terminal, to a file or both.  

```
m477@Coding:~/Documents/Python/Coloured_Logging$ python3 src/coloured_example.py --help
usage: coloured_example.py [-h] [-l LOGFILE] [-s [SILENT ...]] [-d [DEBUG ...]]

An example of coloured logging in Python.

options:
  -h, --help            show this help message and exit
  -l LOGFILE, --logfile LOGFILE
                        Log file for application.
  -s [SILENT ...], --silent [SILENT ...]
                        Display no output to terminal
  -d [DEBUG ...], --debug [DEBUG ...]
                        Display output to file and terminal

```
As you can see I have created 3 arguments that can be supplied via the command line at time of execution.  
&nbsp;  

**No Arguments**  
Running the script with no arguments results in the coloured logging being printed to the terminal window. 
<p><pre>
<font color="#26A269"><b>m477@Coding</b><b></font></font>:<font color="#12488B"><b>~/Documents/Python/Coloured_Logging</b><b></font><font>$ python3 src/coloured_example.py 
<font color="#26A269">[19-06-2023 10:03:55]</font> [INFO]: This is info...
<font color="#26A269">[19-06-2023 10:03:55]</font> <font color="#26A269">[DEBUG]: This is debug...</font>
<font color="#26A269">[19-06-2023 10:03:55]</font> <font color="#A2734C">[Warning]: This is a warning...</font>
<font color="#26A269">[19-06-2023 10:03:55]</font> <font color="#C01C28">[ERROR]: This is an error...</font>
<font color="#26A269">[19-06-2023 10:03:55]</font> <font color="#C01C28"><b>[CRITICAL]: PermissionError: [Errno 13] Permission denied</b></font>
</pre></p>
&nbsp;  

**Silent Argument**  
Running the script with the silent argument prevents any output being logged to the terminal window, instead the coloured logging is written to the default log file.  
<p><pre><font color="#26A269"><b>m477@Coding</b></font>:<font color="#12488B"><b>~/Documents/Python/Coloured_Logging</b></font>$ python3 src/coloured_example.py --silent
<font color="#26A269"><b>m477@Coding</b></font>:<font color="#12488B"><b>~/Documents/Python/Coloured_Logging</b></font>$ cat src/logs/app.log 
<font color="#26A269">[19-06-2023 10:11:51]</font> [INFO]: This is info...
<font color="#26A269">[19-06-2023 10:11:51]</font> <font color="#26A269">[DEBUG]: This is debug...</font>
<font color="#26A269">[19-06-2023 10:11:51]</font> <font color="#A2734C">[Warning]: This is a warning...</font>
<font color="#26A269">[19-06-2023 10:11:51]</font> <font color="#C01C28">[ERROR]: This is an error...</font>
<font color="#26A269">[19-06-2023 10:11:51]</font> <font color="#C01C28"><b>[CRITICAL]: PermissionError: [Errno 13] Permission denied</b></font>
</pre></p>
&nbsp;  

**Debug & Logfile Arguments**  
Executing the script with the debug argument will instruct the script to print output to the terminal window as well as to write logging entries to a file. As I have also specified the logfile in the command, this is where the log entries will be written to.  
<p><pre><font color="#26A269"><b>m477@Coding</b></font>:<font color="#12488B"><b>~/Documents/Python/Coloured_Logging</b></font>$ python3 src/coloured_example.py --debug --logfile ./src/logs/debug.log
<font color="#26A269">[19-06-2023 10:13:58]</font> [INFO]: This is info...
<font color="#26A269">[19-06-2023 10:13:58]</font> <font color="#26A269">[DEBUG]: This is debug...</font>
<font color="#26A269">[19-06-2023 10:13:58]</font> <font color="#A2734C">[Warning]: This is a warning...</font>
<font color="#26A269">[19-06-2023 10:13:58]</font> <font color="#C01C28">[ERROR]: This is an error...</font>
<font color="#26A269">[19-06-2023 10:13:58]</font> <font color="#C01C28"><b>[CRITICAL]: PermissionError: [Errno 13] Permission denied</b></font><br>
<font color="#26A269"><b>m477@Coding</b></font>:<font color="#12488B"><b>~/Documents/Python/Coloured_Logging</b></font>$ cat src/logs/debug.log 
<font color="#26A269">[19-06-2023 10:13:58]</font> [INFO]: This is info...
<font color="#26A269">[19-06-2023 10:13:58]</font> <font color="#26A269">[DEBUG]: This is debug...</font>
<font color="#26A269">[19-06-2023 10:13:58]</font> <font color="#A2734C">[Warning]: This is a warning...</font>
<font color="#26A269">[19-06-2023 10:13:58]</font> <font color="#C01C28">[ERROR]: This is an error...</font>
<font color="#26A269">[19-06-2023 10:13:58]</font> <font color="#C01C28"><b>[CRITICAL]: PermissionError: [Errno 13] Permission denied</b></font>
</pre></p>  

&nbsp;  

### The Code
To implement coloured logs you are required to install the coloredlogs package from the Python package index, the other packages we use including logging are distributed as part of the standard Python3 library.  

```
$ pip3 install coloredLogs
```  
Install the 'coloredLogs' package using pip.  
&nbsp;  

```python
import os
from argparse import ArgumentParser
import logging
import logging.config

LOG_DIRECTORY = os.path.join(os.path.abspath(os.path.dirname(__file__)), "logs")
EXAMPLE_CRITICAL_MESSAGE = "PermissionError: [Errno 13] Permission denied"
```
For this demonstration I import 'os' and 'ArumentParser' to perform basic filepath operations, access checking and command line argument parsing. Additionally I import 'logging' and the 'config' module also from the logging library to parse the configuration options and initiate our logger object. 
The constant values are for a default log directory and an example of a critical error message.  
&nbsp;  

```python
# Test if the directory in the filepath supplied exists and is writable
def invalid_filepath(arg): 
    log_dir = os.path.split(os.path.abspath(arg))[0]
    if not os.path.isdir(log_dir) or not os.access(log_dir, os.W_OK):
        raise ValueError("Invalid log directory")

    return arg


# Accept command line arguments using Argument parser
parser = ArgumentParser(description="An example of coloured logging in Python.")
parser.add_argument(
                    "-l", "--logfile",
                    help="Log file for application.",
                    type=invalid_filepath,
                    required=False
                    )
parser.add_argument(
                    "-s", "--silent",
                    help="Display no output to terminal",
                    action="store",
                    nargs="*"
                    )
parser.add_argument(
                    "-d", "--debug",
                    help="Display output to file and terminal",
                    action="store",
                    nargs="*"
                    )
args = parser.parse_args()
```  
The 'invalid_filepath' function will be called when the arguments are parsed, the function will test if the path supplied is a valid directory and if we have write access to that directory. The arguments are simply to provide an idea of how the output location from the application can be controlled.  
&nbsp;  

```python
# Logging configuration dictionary
log_config = {
                "version": 1,
                "root": {
                    "handlers": [],
                    "level": "DEBUG"
                },
                "handlers": {
                    "console": {
                        "formatter": "coloured_output",
                        "class": "logging.StreamHandler",
                        "level": "DEBUG"
                    },
                    "file": {
                        "formatter": "coloured_output",
                        "class": "logging.handlers.RotatingFileHandler",
                        "level": "DEBUG",
                        "filename": os.path.join(LOG_DIRECTORY, "app.log"),
                        "maxBytes": 1024*1024,
                        "backupCount": 1,
                        "encoding": "utf-8"    
                    }
                },
                "formatters": {
                    "coloured_output": {
                        "()": "coloredlogs.ColoredFormatter",
                        "format": "[%(asctime)s] %(message)s",
                        "datefmt": "%d-%m-%Y %H:%M:%S",
                    }
                }
            }
```
Here is the logging configuration stored in a Python dictionary, this is a very basic configuration consisting of 2 handlers:  
* Console - Handles output to the console window.  
* File - Handles output to a log file and manages file size and rotation.  

The 'coloured_output' formatter is where the logging message format is defined, this is where the coloredLogs package is called to wrap the message format.  
[Logging Config Documentation](https://docs.python.org/3/library/logging.config.html)  
&nbsp;  

```python
def parse_logging_config(args):

    if args.silent is not None:
        log_config['root']['handlers'].append("file")
        if args.logfile:
            log_config['handlers']["file"]["filename"] = args.logfile
    
    elif args.debug is not None:
        log_config['root']['handlers'].append("console")
        log_config['root']['handlers'].append("file")
        if args.logfile:
            log_config['handlers']["file"]["filename"] = args.logfile

    elif args.logfile:
        log_config['root']['handlers'].append("file")
        log_config['handlers']["file"]["filename"] = args.logfile
    
    else:
        log_config['root']['handlers'].append("console")

    return log_config
```
This function will modify the logging dictionary configuration to match any command line arguments supplied when the script is executed.  
&nbsp;  

```python
# Load config from dictionary, modifying configuration to meet command line arguments
def load_logging_config(config_dict):
    try:
        logging.config.dictConfig(parse_logging_config(args=args))
        logger = logging.getLogger(__name__)

    except Exception as error:
        print(f"[ERROR]: If running as root you must install package as root: 'sudo pip3 install coloredlogs'\n\t\t\t{error}")
        exit()
```
This function will attempt to get the logging configuration options from the 'config_dict' and then create a logging instance, it is wrapped in a try / except block to catch an error thrown when the script is being executed as root.  
&nbsp;  

```python
# Logging Message examples
def print_demo():
    logging.info("[INFO]: This is info...")
    logging.debug("[DEBUG]: This is debug...")
    logging.warning("[Warning]: This is a warning...")
    logging.error("[ERROR]: This is an error...")
    logging.critical(f"[CRITICAL]: {EXAMPLE_CRITICAL_MESSAGE}")
```
Various severity-level logging messages to demonstrate the coloured logging output.  
&nbsp;  

```python
def main():
    load_logging_config(log_config)
    print_demo()


if __name__ == "__main__":
    main()

```  
A main function to tie it all in together, parsing the configuration then demonstrate the various severity logging messages.  
&nbsp;  

### Further Information
[**Example Repository - GitHub**]()  
[**Coloured Logs - PyPi**](https://pypi.org/project/coloredlogs/)  
