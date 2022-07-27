# PyPI

Install package from local pypi:
`pip install --trusted-host <ip> --index-url <url> <package>`

Configure local repo as default and trusted:
place pip.conf under /etc/

Search packages:
`pip search <package>`

List packages:
`curl <ip>/simple/`
`curl <ip>/packages/`

Download package:
`pip download <package>`

Install location:
usr/local/lib/python3.6/dist-packages/package
