# TLSproxy makes TLS trivial

SSL/TLS is difficult to setup correctly:

- SSL/TLS configuration options are too numerous to cite
- each web server has its own set of options
- certificates expire and must be renewed (but see [SSLPing](https://sslping.com) )
- certs cost money
- it's too hard to obtain a secure TLS configuration

TLSproxy makes it trivially simple to secure a web server: it has only one option, to provide your email (sent only to Let's Encrypt).

TLSproxy intends to solve a basic use-case: when you need to secure a single webserver with support for virtual hosts. In this case, it does wonders.

# Binaries

[You can download binaries for Linux-amd64 and OSX-amd64](https://github.com/chrisDeFouRire/tlsproxy/releases)

Or build TLSproxy yourself from the Go source code.

# Howto

Just run TLSproxy alongside your webserver which should be serving traffic on localhost:80.

`sudo ./TLSproxy -email info@tlsproxy.com` should be enough to check if it works for you, then deploy it with upstart or systemd. It will store certificates in a `./certs` folder (please secure this folder!).

If your DNS is already configured and your webserver is already serving traffic on port 80, TLSproxy will handle the TLS/SSL part transparently. It will request Let's Encrypt certs (even for virtual hosts!) automatically, it will renew certs automatically, and proxy all the traffic to your webserver. Even WebSockets will work.

# Caveats

You must run TLSproxy as root, or set capabilities to allow it to bind to port 443.

```
setcap 'cap_net_bind_service=+ep' /path/to/TLSproxy
```

Because TLSproxy is a TCP level proxy, your webserver can't determine the client's IP address anymore. TLSproxy is **not** an HTTP proxy.

Also, there's a possibility of DoS if an attacker sends SNI requests forcing TLSproxy to request many certificates (cf. Let's Encrypt rate limiting).

# License etc.

You can do whatever you want with TLSproxy but you must assume responsibility for everything.

You can [hire me if you need professional support](https://hire.chris-hartwig.com).

Make a Bitcoin donation to say "Thanks" :-)

![1A4ZNLXBYP8m1HL7RsCwHDU8Thuhx6YXcQ`](./BTCtlsproxy.png)