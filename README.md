# Ruse - a multi-platform HTTP Redirector
Ruse is an open source, multi-platform HTTP redirector that make it easy to
conceal C2 or shellcodes listeners using the Hypertext Transfer Protocol.

Ruse supports both plain-text HTTP and HTTPS, in a simple to use
multi-platform server executable. Ruse can be rapidly deployed from the
command-line or inside a Docker container for even more security.

## Features
 * Runs under Linux \*BSD, MacOS, and Windows (Win7, Server 2008R2 and later)
 * No external dependencies
 * HTTP and HTTPS (SSL/TLS) support
 * Selective Reverse Proxying
 * Serve static files (with optional directory listing)
 * File Logging
 
## Why
Ruse helps you overcome multiple challenges, such as:
 * Hiding your HTTP listener(s) from Incident Response teams.
 * Load-balance to multiple remote listeners.
 * Simultaneously serving static files and listening for reverse HTTP shellcode on a single port.
 * Leveraging domain-fronting by only exposing the redirector to the world.

If you're doing Red Team operations or you may simply want to hide your HTTP
listener during an engagement, Ruse may be of help.

In fact, you may want incident response teams or your targets' operators not to
directly contact your C2 or metasploit HTTP listener for various reasons, such
as limiting your fingerprint or to fool them by serving or proxying traffic to
a legimate web site.

## Building from source
To build Ruse from source, simply enter:
```
$ make build
building: bin/amd64/ruse
```

## Running from the command-line: 
Ruse can run unprivileged from a terminal:
```
$ bin/amd64/ruse -c conf/ruse.conf
Starting HTTP Server on 0.0.0.0:8000
```
By default Ruse is configured to listen on port tcp/8000 and only accept
plain-text HTTP connections from clients. It's also configured to proxy traffic
from metasploit's reverse HTTP payloads by matching their User-Agent header
fields.

## Building and running under Docker:
Ruse can also run under a Docker container, and thus in a matter of seconds:
```
$ make container
building: bin/amd64/ruse
Sending build context to Docker daemon  31.29MB
Step 1/6 : FROM alpine
 ---> 196d12cf6ab1
Step 2/6 : MAINTAINER Evil Duck
 ---> Running in 316636af5aec
Removing intermediate container 316636af5aec
 ---> accc21a45d03
Step 3/6 : ADD bin/amd64/ruse /ruse
 ---> d9f9d36cfb71
Step 4/6 : RUN mkdir /var/www
 ---> Running in d8de6e8333aa
Removing intermediate container d8de6e8333aa
 ---> 008182dded9d
Step 5/6 : USER nobody:nobody
 ---> Running in 5bcd97b5855e
Removing intermediate container 5bcd97b5855e
 ---> f50761fd621c
Step 6/6 : ENTRYPOINT ["/ruse"]
 ---> Running in 6eb47e4dc6c9
Removing intermediate container 6eb47e4dc6c9
 ---> e18c33f2ec0d
Successfully built e18c33f2ec0d
Successfully tagged registry/ruse-amd64:59ea848-dirty
container: registry/ruse-amd64:59ea848-dirty

$ docker run -v `pwd`/conf/ruse.conf:/etc/ruse.conf -p 127.0.0.1:8000:8000/tcp registry/ruse-amd64:59ea848-dirty
Starting HTTP Server on 0.0.0.0:8000
```

## Configuring
To configure the redirector, copy and edit the [ruse.conf](conf/ruse.conf)
configuration file inside the `/conf` directory to `/etc/ruse.conf`. The latter
is the default configuration file path, and can be manually changed using the
command-line switch `-c`.

The configuration file is in JSON format, and accepts various configuration
options, please see the tables below for further reference:

configuration attributes
------------------------
| Attribute Name | Required | Default value | Supported value / description      |
|----------------|----------|---------------|------------------------------------|
| Hostname       | Yes      | 0.0.0.0       | hostname or IP address             |
| Protocols      | Yes      | plain         | plain, tls                         |
| Port           | Yes      | 8000          | 0-65535                            |
| TLSPort        | No       | 8443          | 0-65535                            |
| TLSKey         | No       | server.key    | PEM private key                    |
| TLSCert        | No       | server.crt    | PEM X.509 certificate              |
| Root           | No       | /var/www      | static content root directory      |
| Index          | No       | index.htm     | directory index file               |
| Verbose        | Yes      | 2             | 0(off), 1(low), 2(medium), 3(high) |
| Logfile        | No       |               | readable and writable log file     |
| Proxy          | No       | msf default   | See proxy sub-attributes table     |

proxy sub-attributes
--------------------
| Sub-attribute Name | Required | Default value                   | Supported value or description          |
|--------------------|----------|---------------------------------|-----------------------------------------|
| type               | Yes      | reverse                         | reverse                                 |
| description        | No       |                                 | administrative description of the proxy |
| match              | Yes      | Mozilla/5.0 (Windows NT 6.1;... | valid UA string                         |
| target             | Yes      | http://msf.toor.si:80           | valid http:// or https:// scheme URI    |

## Contributing
If you find this project useful and want to contribute, we will be more than
happy to receive your contribution in the form of code, documentation and even
bug reports. To contribute code, feel free to fork this project and send your
pull request(s).

