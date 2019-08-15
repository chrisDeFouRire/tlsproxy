# TLSproxy makes TLS trivial

SSL/TLS is difficult to setup correctly:

- SSL/TLS configuration options are too numerous to cite
- each web server has its own set of options
- certificates expire and must be renewed (but see [SSLPing](https://sslping.com) )
- certs cost money
- it's too hard to obtain a secure TLS configuration

TLSproxy makes it trivially simple to secure a web server: it has only one option, to provide your email (sent only to Let's Encrypt).

TLSproxy intends to solve a basic use-case: when you need to secure a single webserver with support for virtual hosts. In this case, it does wonders.

# Run with Docker

It's easy to run TLSproxy in docker!

`docker pull tlsproxy/tlsproxy` will pull the image from the official repository.

Now run Docker alongside the container you want to protect with TLS...

**Example with nginx:**
```
docker run -d --name mynginx -p 0.0.0.0:80:80 nginx
docker run -d --name tlsmynginx -e EMAIL=youremail@a-domain.com -e BACKEND=http://mynginx:80 -p 0.0.0.0:443:443 -e PROXY=true tlsproxy/tlsproxy
```

This will run a tlsproxy container which will forward TCP requests to the `mynginx` container... Env variables (BACKEND HTTP and EMAIL) are used to tell tlsproxy what should be proxied and how...

If you want your LetsEncrypt certs stored on the host instead of inside the container (highly recommended), just add a `-v /anyfolder/certs:/go/src/app/certs` to map the volume used to store certs on the host. Using a volume helps update tlsproxy without deleting every cert already obtained through LetsEncrypt (beware of LE rate limits).

# Binaries

You'll have to build TLSproxy yourself from the Go source code: I do recommend using Docker if you can.

### Options

You can use flags or environment variables...

- `-hostname=<host>` or `HOSTNAME`: the hostname used for the tls certificate (if omitted, the server will guess which tls cert it should acquire... which may fail or be abused)
- `-email=<email>` or `EMAIL`: the email to use when registering new certs with LetsEncrypt
- `-listen=host:port` or `LISTEN`: the host and port where TLSproxy will listen (defaults to 0.0.0.0:443)
- `-backend=http://host:port` or `-backend=host:port` or `BACKEND`: the address of the backend to forward to (defaults to localhost:80 for TCP proxying) 
- `-http=true` or `HTTP=true`: set to true to use HTTP proxying instead of TCP proxying (defaults to false)
- `-proxy=true` or `PROXY=true`: set to true to allow TCP proxying with the PROXY protocol
- `-har=true` or `HAR=true`: when true, TLSProxy will keep track of all requests until you call `GET /downloadharfile`. It will return a JSON HTTP Archive (HAR)file which can be opened with Chrome Dev tools to inspect each request. This is very useful, but for development only

# Roadmap

Next on the roadmap:

- use store for shared certificates (Redis? other?)

# License etc.

You can do whatever you want with TLSproxy but you must assume full responsibility, ie. I'm not liable.

You can [hire me if you need professional support](https://hire.chris-hartwig.com).

Or make a Bitcoin donation to say "Thanks" :-)

![1A4ZNLXBYP8m1HL7RsCwHDU8Thuhx6YXcQ](./BTCtlsproxy.png)
