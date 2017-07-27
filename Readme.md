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

`sudo ./TLSproxy -email youremail@a-domain.com` should be enough to check if it works for you, then deploy it with upstart or systemd. It will store certificates in a `./certs` folder (please secure this folder!).

If your DNS is already configured and your webserver is already serving traffic on port 80, TLSproxy will handle the TLS/SSL part transparently. It will request Let's Encrypt certs (even for virtual hosts!) automatically, it will renew certs automatically, and proxy all the traffic to your webserver. Even WebSockets will work.

### Options

You can use environment variables or flags...

- `-email=<email>` or `EMAIL`: the email to use when registering new certs with LetsEncrypt
- `-listen=host:port` or `LISTEN`: the host and port where TLSproxy will listen (defaults to 0.0.0.0:443)
- `-backend=http://host:port` or `BACKEND`: the address of the backend to forward to (defaults to localhost:80) 
- `-http=true` or `HTTP`: set to true to use HTTP proxying instead of TCP proxying (defaults to false)

# Run with Docker

It's even easier to run TLSproxy in docker!

`docker pull tlsproxy/tlsproxy` will pull the image from the official repository.

Now run Docker alongside the container you want to protect with TLS...

**Example with nginx:**
```
docker run -d --restart=always --name mynginx -p 0.0.0.0:80:80 nginx
docker run -d --restart=always --name tlsmynginx -e EMAIL=youremail@a-domain.com --link mynginx -e BACKEND=http://mynginx:80 -p 0.0.0.0:443:443 -e HTTP=true tlsproxy/tlsproxy
```

This will run a tlsproxy container, linked to the `mynginx` container... Env variables (BACKEND HTTP and EMAIL) are used to tell tlsproxy what should be proxied and how...

If you want your LetsEncrypt certs stored on the host instead of inside the container (highly recommended), just add a `-v /anyfolder/certs:/go/src/app/certs` to map the volume used to store certs on the host. Using a volume helps update tlsproxy without deleting every cert already obtained through LetsEncrypt (beware of LE rate limits).

# Caveats

You must run TLSproxy as root, or set capabilities to allow it to bind to port 443, or change the listen address to an unpriviledged port... To allow TLSproxy to bind to priviledged ports, you can use:

```
setcap 'cap_net_bind_service=+ep' /path/to/TLSproxy
```

Also, there's a possibility of DoS if an attacker sends SNI requests forcing TLSproxy to request many certificates (see below, we're working on it).

TLSproxy doesn't load balance traffic... Build your HTTP load balancing separately, then add TLSproxy in front of it. You'll get HTTP and HTTPS load balancing that way.

# Roadmap

Next on the roadmap:

- use stores for certificates (Vault? Redis? other?)
- allow reusing existing certs (yet allow LE certs if needed)
- allow restricting domain issuing (regexp? list? webhook?)
- build the [tlsproxy.com](https://tlsproxy.com) website... It's empty right now, but with TLSproxy of course
- add prometheus monitoring
- optimize and benchmark
- and more... Tell us what you need! 

# License etc.

You can do whatever you want with TLSproxy but you must assume full responsibility for everything you do with it.

You can [hire me if you need professional support](https://hire.chris-hartwig.com).

Or make a Bitcoin donation to say "Thanks" :-)

![1A4ZNLXBYP8m1HL7RsCwHDU8Thuhx6YXcQ](./BTCtlsproxy.png)