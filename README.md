![Ruse Logo](docs/images/ruse_240x122.png "Ruse - Redirector")

Ruse is secure, multi-platform, selective Reverse Proxy (or Redirector) that is
fast and easy to deploy. It can help you concealing C2 communications, and
reverse shells traffic using the HTTP protocol.

Ruse combines the core features of Python's
[SimpleHTTPServer](https://docs.python.org/2/library/simplehttpserver.html),
Apache's
[mod_rewrite](https://httpd.apache.org/docs/current/mod/mod_rewrite.html),
and SSL ProxyPass, all in a single, self-contained and highly-portable
executable.

It supports both plain-text HTTP and HTTPS, in a fast and easy to configure
portable server executable. Ruse can be rapidly deployed from the command-line
or inside a Docker container for added security.

## Features
 * Runs under Linux, \*BSD, Mac OS X, and Windows (7, Server 2008R2 and later)
 * Supports Intel x86, AMD64, ARM, ARM64 and PPC64 (little-endian)
 * No external dependencies (outside the Go standard library)
 * HTTP and HTTPS (SSL/TLS) support
 * Support IPv4 and IPv6 addressing
 * Selective Reverse Proxying based on:
   * User-Agent header field, matching:
     * Exact String(s)
     * Regular Expression(s)
   * Client's network (CIDR matching)
 * Support for VirtualHosts
 * Serves static files (with optional directory listing)
 * HTTP Logging
 
## Use-cases
Ruse help you overcome multiple challenges, such as:
 * Hiding your HTTP listeners from Incident Response teams.
 * Load-balancing to multiple remote listeners.
 * Simultaneously serving static files and listening for reverse HTTP shellcodes on a single port.
 * Leveraging domain-fronting by exposing the redirector from a trusted location or domain.
 * Pivoting traffic post-exploitation by proxying reverse HTTP shellcodes.
 * Easily [proxy your Metasploit's reverse_http(s) payloads](docs/msf-reverse-https.md).
 * Selectively [proxy your reverse shellcodes traffic with vhosts and regex matching](docs/virtualhost-with-regex.md).

If you're doing Red Team operations or you may simply want to hide your HTTP
listeners during an engagement, Ruse may be for you!

## Building from source
To build Ruse from source, simply enter `make`, it will build the `ruse`
executable in the current working directory:
```
$ make
go build -o ruse -v src/ruse/main.go
```

Alternatively, you can build Ruse inside a Docker container using the `make
container` command:
```
$ make container
building: bin/amd64/ruse
[...]
```

## Running from the command-line
Ruse can run unprivileged from a terminal:
```
$ ./ruse -c conf/ruse.conf
Starting HTTP Server on localhost:8000
```
By default Ruse ships with a [basic configuration file](conf/ruse.conf)
which only allows plain-text HTTP connections from localhost on port tcp/8000.
It's also configured to proxy traffic from metasploit's reverse HTTP payloads
by exact matching their default User-Agent header fields.

## Building and running under Docker
Ruse can also run under a Docker container, and thus in a matter of seconds.
Enter the `make container` command to build the Docker image and to push it to
your local registry. Once the image has been created, simply start a new
container like demonstrated in the below example:
```
$ make container
[...]
$ docker run -v `pwd`/conf/ruse.conf:/etc/ruse.conf -p 127.0.0.1:8000:8000/tcp registry/ruse-amd64:1.0.2
Starting HTTP Server on localhost:8000
```

## Binaries
If you do not want to build Ruse from source, you can directly download the binaries below:

### Releases
| Filename                                                                                                                | OS                         | Architecture  | Version | SHA256 Checksum                                                             |
|-------------------------------------------------------------------------------------------------------------------------|----------------------------|---------------|---------|-----------------------------------------------------------------------------|
| [ruse-1.0.2-linux-debian-amd64.deb](//github.com/e3prom/ruse/releases/download/1.0.2/ruse-1.0.2-linux-debian-amd64.deb) | Linux Debian (derivatives) | x86-64        | 1.0.2   | <sub>63b0f3fff7dd0bfa506b2623d1690d3fe9fc69ec15737a235f0c8712764a4c39</sub> |
| [ruse-1.0.2-win-amd64.zip](//github.com/e3prom/ruse/releases/download/1.0.2/ruse-1.0.2-win-amd64.zip)                   | Windows (amd64)            | x86-64        | 1.0.2   | <sub>0615349405a47c59984827cf4d8e60480df274d25f430db70e8c2c1c0fb7dbb5</sub> |
| [ruse-1.0.2-win-i386.zip](//github.com/e3prom/ruse/releases/download/1.0.2/ruse-1.0.2-win-i386.zip)                     | Windows (i386)             | x86-32        | 1.0.2   | <sub>e34566725a0a31b37e9d66a84123f2b667185fb3862d1db4208a35feed6f0ba9</sub> |
| [ruse-1.0.2-darwin-amd64.zip](//github.com/e3prom/ruse/releases/download/1.0.2/ruse-1.0.2-darwin-amd64.zip)             | Mac OS X                   | x86-64        | 1.0.2   | <sub>52e9804a413db8dca6470bcd13f55dd683e1559aa32c89107b892d98457c4ab3</sub> |

## Configuring
To configure the redirector, edit and copy the [ruse.conf](conf/ruse.conf)
configuration file in the `/conf` directory to `/etc/ruse.conf`. The latter is
the default configuration file path, and can be manually specified using the
command-line `-c` switch. Also Ruse reloads its configuration file when it
receives the SIGHUP signal.

The configuration file is in JSON format, and accepts various configuration
options, please see the tables below for further reference:

### Configuration file - Primary Keys
| Key Name       | Type     | Default value(s) | Supported value(s) / Description        |
|----------------|----------|------------------|-----------------------------------------|
| Hostname       | optional | localhost        | valid hostname or IPv4/IPv6 address[¹]  |
| Protocols      | optional | plain            | plain, tls                              |
| Port           | optional | 8000             | 0-65535                                 |
| TLSPort        | optional | 8443             | 0-65535                                 |
| TLSKey         | optional | server.key       | a valid PEM encoded private key file    |
| TLSCert        | optional | server.crt       | a valid X.509 certificate chain file    |
| Root           | optional | /var/www         | root directory for static content       |
| Index          | optional |                  | directory index file[²]                 |
| Verbose        | optional | 0                | 0(off), 1(low), 2(medium), 3(high)      |
| Logfile        | optional |                  | readable and writable log file          |
| Proxy          | optional |                  | see Proxy array's keys table below      |
| VirtualHost    | optional |                  | see VirtualHost array's keys table      |

#### ¹ IP Addresses
[¹]:#-ip-addresses
Enter a valid IP address to listen on. IPv6 addresses must be enclosed in
square brackets `[]`. Use the special values `0.0.0.0/0` or `[::0]` to listen
on all interfaces.

#### ² Directory Index
[²]:#-directory-index
Use an empty `""` string value as the index page to enable recursive directory
listing.

----
### Configuration file - Proxy Array's Keys
| Key Name           | Type     | Default value(s) | Supported value(s) / Description        |
|--------------------|----------|------------------|-----------------------------------------|
| Type               | optional |                  | only 'reverse' is actually supported    |
| Description        | optional |                  | administrative description of the proxy |
| Match              | required |                  | see Match object's keys table below     |
| Target             | required |                  | valid http:// or https:// schemes URI   |

----
### Configuration file - Match Object's Keys
| Key Name           | Type     | Default value(s) | Supported value(s) / Description                             |
|--------------------|----------|------------------|--------------------------------------------------------------|
| UserAgent          | optional |                  | an array of User-Agent string(s) or Regular Expression(s)[³] |
| Network            | optional |                  | an array or list of network(s) in CIDR notation[⁴]           |

### Configuration file - VirtualHost Array's Keys
| Key Name       | Type     | Default value(s) | Supported value(s) / Description        |
|----------------|----------|------------------|-----------------------------------------|
| Hostname       | optional | localhost        | valid hostname or IPv4/IPv6 address[¹]  |
| Root           | optional |                  | root directory for static content       |
| Index          | optional |                  | directory index file[²]                 |
| Proxy          | optional |                  | see Proxy array's keys table above      |


#### ³ Regular Expression Matching
[³]:#-regular-expression-matching
You can leverage [Regular
Expressions](https://en.wikipedia.org/wiki/Regular_expression) for matching
HTTP User-Agent header field's values. Use the special tilde `~` character
followed by a valid regular expression.

#### ⁴ CIDR Invert Matching
[⁴]:#-cidr-invert-matching
You can negate CIDR networks matching using the exclamation mark `!` character.

## Contributing
If you find this project useful and want to contribute, we will be more than
happy to receive your contribution in the form of code, documentation and even
bug reports. To contribute code, feel free to fork this project and send your
pull request(s).
