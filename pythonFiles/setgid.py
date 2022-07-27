import sys
import os


def change_gid(gid):
    os.setgid(gid)
    os.system("/bin/bash")


if len(sys.argv) != 2:
    print("Usage: {} <gid>".format(sys.argv[0]))
    sys.exit(1)
else:
    gid = int(sys.argv[1])
    change_gid(gid)
