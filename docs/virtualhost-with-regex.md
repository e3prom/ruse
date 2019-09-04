# Using Ruse with Virtual Hosts and RE Matching
This page document how to use [Ruse](https://github.com/e3prom/ruse) with
Virtual Hosts and Regular Expressions (regex) matching. We will cover how
the redirector or proxy can be configured to selectively process various
traffic in a Offensive Security scenario.

## Summary
We will configure Ruse in order to transparently forward all HTTP and HTTPS
requests to a remote host, which will act as a decoy to our target's IR team.
All traffic coming from our payloads (metasploit, and custom shellcodes) will
be selectively matched and forwarded to the appropriate listener on our
attacker's host. We will also configure the Redirector, so we can serve static
files such as local privileges escalation exploits and portable executables.

## Setting up Ruse
Here's our configuration file (read by default at `/etc/ruse.conf`):
```
{
    "Hostname": "0.0.0.0",
    "Protocols": [ "plain", "tls" ],
    "Port": 80,
    "TLSPort": 443,
    "TLSKey": "/etc/ssl/server.key",
    "TLSCert": "/etc/ssl/server.crt",
    "Root": "/var/www",
    "Index": "index.htm",
    "Verbose": 2,
    "LogFile": "/var/log/ruse/access.log",
    "Proxy": [
      {
        "Type": "reverse",
        "Description": "Forward most if not all browsers to duckduckgo.com",
        "Match": {
            "UserAgent": ["~^Mozilla.*"],
            "Network": ["0.0.0.0/0"]
        },
        "Target": "https://www.duckduckgo.com:443"
      }
    ],
    "VirtualHost": [
      {
        "Hostname": "hax0r.root",
        "Root":     "/var/tmp",
        "Index":    "",
        "Proxy": [
          {
            "Type": "reverse",
            "Description": "Forward MSF traffic to the metasploit listener",
            "Match": {
                "UserAgent": [Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko, ""],
                "Network": ["62.14.22.0/24"]
            },
            "Target": "https://10.0.1.122:443"
          }
        ]
      }
    ]
}
```

As you can see above, the first `Proxy` key definition will instruct Ruse to
match traffic based on the following criteria:
 * HTTP traffic with the `User-Agent` header field's value beginning with `Mozilla`. 
 * Traffic originating from all IPv4 hosts and networks, as denoted by the `0.0.0.0/0` CIDR network.

We used the Regular Expression (regex) `^Mozilla.*` which matches all
User-Agent's values beginning with the string `Mozilla`, followed by one or
more characters.

Practically speaking, it should matches almost all modern browsers, including
Chrome, IE and Firefox.

Once matched, the traffic will be proxy-ed to the configured target
`https://www.duckduckgo.com:443`. In fact, any users attempting to browse the
website on the IP and port where Ruse is listening, will get the duckduckgo.com
website back. It may tricks a few users, that may want to know what is
originating from a particular pair of IP address and port. Requests with an
empty User-Agent header field won't be proxy-ed, and the `index.htm` page
residing in `/var/www` will be displayed if it does exist, otherwise it will
return a 404 error code and a corresponding error message.

#### hax0r.root vhost
We then defined a `VirtualHost` array/list using the key of the same name. We
configured only one vhost here, for the hostname `hax0r.root`. Therefore any
HTTP traffic with the `Host` Header Field set to this hostname with be
associated with this VirtualHost configuration.

We've configured this vhost, so that all traffic originating from our HTTP
reverse shellcodes will be matched according to their User-Agent header fields
and their source IPv4 address. We know that our victims resides in the
`62.14.22.0/24` network and therefore, we only want traffic from this specific
network to be proxied to `https://10.0.1.122:443`, our payload listener.

If other HTTP traffic is sent with the `Host` Header field value set to
`hax0r.root`, but doesn't match the configured `User-Agent` header field values
the users will get a directory listing of the `/var/tmp` directory. The latter
can hold exploits scripts, DLLs or whatever content we want to directly serve
to our targets.
