# Ruse - a multi-platform HTTP Redirector
Ruse is an open source, multi-platform HTTP redirector that make it easy to
conceal C2 or shellcodes listeners using the Hypertext Transfer Protocol.

It combines the Python's
[SimpleHTTPServer](https://docs.python.org/2/library/simplehttpserver.html),
[mod_rewrite](https://httpd.apache.org/docs/current/mod/mod_rewrite.html),
and Apache's SSL ProxyPass features, all in a single tool.

Ruse supports both plain-text HTTP and HTTPS, in a fast and easy to configure
multi-platform server executable. Ruse can be rapidly deployed from the
command-line or inside a Docker container for even more security.

## Features
 * Runs under Linux, \*BSD, MacOS, and Windows (Win 7, Server 2008R2 and later)
 * Supports AMD64, ARM, ARM64 and PPC64 (little-endian)
 * No external dependencies
 * HTTP and HTTPS (SSL/TLS) support
 * Support IPv4 and IPv6 addressing
 * Selective Reverse Proxying based on:
   * User-Agent String(s)
   * CIDR Network(s)
 * Serves static files (with optional directory listing)
 * File Logging
 
## Use-cases
Ruse helps you overcome multiple challenges, such as:
 * Hiding your HTTP listener(s) from Incident Response teams.
 * Load-balancing to multiple remote listeners.
 * Simultaneously serving static files and listening for reverse HTTP shellcodes on a single port.
 * Leveraging domain-fronting by exposing the redirector from a trusted location.
 * Pivoting post-exploitation by proxying reverse HTTP(S) shellcodes.
 * Quickly [proxy your Metasploit's reverse_http(s) payloads](examples/msf-reverse-https.md).

If you're doing Red Team operations or you may simply want to hide your HTTP
listeners during an engagement, Ruse may be of help.

In fact, you may want incident response teams or your targets' operators not to
directly contact your C2 or metasploit HTTP listener for various reasons, such
as limiting your fingerprint or to fool them by serving or proxying traffic to
a legimate web site.

## Building from source
To build Ruse from source using a Docker container, simply enter:
```
$ make build
building: bin/amd64/ruse
```

Alternatively, you can build the `ruse` executable manually using the original Go compiler:
```
$ go build -o ruse src/ruse/main.go
```

## Running from the command-line
Ruse can run unprivileged from a terminal:
```
$ bin/amd64/ruse -c conf/ruse.conf
Starting HTTP Server on localhost:8000
```
By default Ruse ships with an [example configuration file](conf/ruse.conf)
which only allows plain-text HTTP connections from localhost on port tcp/8000.
It's also configured to proxy traffic from metasploit's reverse HTTP payloads
by matching their User-Agent header fields.

## Building and running under Docker
Ruse can also run under a Docker container, and thus in a matter of seconds.
Enter the `make container` command to build the Docker image and to push it to
your local registry. Once the image has been created, simply start a new
container like demonstrated in the below example:
```
$ make container
[...]
$ docker run -v `pwd`/conf/ruse.conf:/etc/ruse.conf -p 127.0.0.1:8000:8000/tcp registry/ruse-amd64:59ea848-dirty
Starting HTTP Server on localhost:8000
```

## Configuring
To configure the redirector, copy and edit the [ruse.conf](conf/ruse.conf)
configuration file in the `/conf` directory to `/etc/ruse.conf`. The latter is
the default configuration file path, and can be manually changed using the
command-line switch `-c`.

The configuration file is in JSON format, and accepts various configuration
options, please see the tables below for further reference:

configuration file - main attributes
------------------------------------
| Attribute Name | Type     | Default value(s) | Supported value(s) / Description        |
|----------------|----------|------------------|-----------------------------------------|
| Hostname       | optional | localhost        | hostname or IPv4 address                |
| Protocols      | optional | plain            | plain, tls                              |
| Port           | optional | 8000             | 0-65535                                 |
| TLSPort        | optional | 8443             | 0-65535                                 |
| TLSKey         | optional | server.key       | PEM private key                         |
| TLSCert        | optional | server.crt       | PEM X.509 certificate                   |
| Root           | optional | /var/www         | static content root directory           |
| Index          | optional |                  | directory index file, use "" to disable |
| Verbose        | optional | 0                | 0(off), 1(low), 2(medium), 3(high)      |
| Logfile        | optional |                  | readable and writable log file          |
| Proxy          | optional | msf default      | See Proxy sub-attributes table          |

configuration file - Proxy sub-attributes
-----------------------------------------
| Sub-attribute Name | Type     | Default value(s) | Supported value(s) / Description        |
|--------------------|----------|------------------|-----------------------------------------|
| Type               | optional |                  | reverse                                 |
| Description        | optional |                  | administrative description of the proxy |
| Match              | required |                  | see Match sub-attribute table           |
| Target             | required |                  | valid http:// or https:// scheme URI    |

configuration file - Match sub-attributes
-----------------------------------------
| Sub-attribute Name | Type     | Default value(s) | Supported value(s) / Description            |
|--------------------|----------|------------------|---------------------------------------------|
| UserAgent          | optional |                  | an array of valid User-Agent string(s)      |
| Network            | optional |                  | an array of network(s) in CIDR notation[¹]  |

#### ¹ CIDR Invert Matching
[¹]:#-cidr-invert-matching
You can negate CIDR networks matching using the exclamation mark `!` character.

## Contributing
If you find this project useful and want to contribute, we will be more than
happy to receive your contribution in the form of code, documentation and even
bug reports. To contribute code, feel free to fork this project and send your
pull request(s).

