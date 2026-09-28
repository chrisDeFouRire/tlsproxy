# TLSproxy makes TLS trivial

SSL/TLS is difficult to set up correctly:

- SSL/TLS configuration options are too numerous to cite
- each web server has its own set of options
- certificates expire and must be renewed (use [SSLPing](https://sslping.com) to remind you)
- certs cost money
- it's too hard to obtain a secure TLS configuration

TLSproxy makes it trivially simple to secure a web server: put it in front of your server, tell it where to forward traffic, and it gets and renews free [Let's Encrypt](https://letsencrypt.org) certificates for you.

TLSproxy intends to solve a basic use case: when you need to secure a single web server with support for virtual hosts. In this case, it does wonders.

## What you get

- Certificates obtained and renewed automatically from Let's Encrypt (TLS-ALPN-01 challenge, on port 443 only, nothing is needed on port 80). ECDSA certificates for modern clients, RSA for older ones.
- TLS 1.3, and TLS 1.2 with forward secret AEAD cipher suites only (`-mintls=1.3` to disable TLS 1.2).
- Post-quantum key exchange: the hybrid `X25519MLKEM768`, `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` groups are offered and preferred, with `X25519`, `P-256` and `P-384` for clients that don't support them yet.
- HTTP/2 to clients in HTTP mode.
- Two modes:
  - **TCP mode** (default): the decrypted stream is forwarded as is to `host:port`, optionally with a [PROXY protocol](https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt) v1 header so the backend knows the client's IP address.
  - **HTTP mode** (`-http=true`): TLSproxy is a reverse proxy to an `http://` or `https://` URL. The `Host` header is kept, and `X-Forwarded-For`, `X-Forwarded-Host` and `X-Forwarded-Proto` are set.

## Run with Docker

Build the image:

```
docker build -t tlsproxy .
```

Then run it alongside the container you want to protect with TLS. The DNS records for your hostnames must point to the Docker host, and port 443 must be reachable from the internet so Let's Encrypt can validate them.

**Example with nginx, in HTTP mode:**

```
docker network create web
docker run -d --name mynginx --network web nginx
docker run -d --name tlsmynginx --network web -p 443:443 \
  -e WHITELIST=www.example.com \
  -e EMAIL=you@example.com \
  -e HTTP=true \
  -e BACKEND=http://mynginx:80 \
  -v /anyfolder/certs:/root/certs \
  tlsproxy
```

**Same thing in TCP mode, with the PROXY protocol:**

```
docker run -d --name tlsmynginx --network web -p 443:443 \
  -e WHITELIST=www.example.com \
  -e BACKEND=mynginx:80 \
  -e PROXY=true \
  -v /anyfolder/certs:/root/certs \
  tlsproxy
```

With `PROXY=true`, the backend must expect the PROXY protocol (for nginx, `listen 80 proxy_protocol;`), or it will reject the connections.

Certificates are stored in `/root/certs` inside the container. Keep them on a volume, as in the examples above (highly recommended): you can then update TLSproxy without requesting every certificate again from Let's Encrypt, which has [rate limits](https://letsencrypt.org/docs/rate-limits/).

A `docker-compose.yml` is included as an example of HTTP mode with HAR recording, in front of an echo server.

## Build from source

TLSproxy needs Go 1.27.1 or later:

```
go build -o tlsproxy .
./tlsproxy -whitelist=www.example.com -http=true -backend=http://localhost:8080
```

It must be reachable on port 443 from the internet for Let's Encrypt to validate your hostnames. If it listens on another port, forward port 443 to it.

## Options

You can use flags or environment variables:

| Flag | Variable | Description |
| --- | --- | --- |
| `-backend` | `BACKEND` | **Required.** Where to forward traffic: `host:port` in TCP mode, `http://host:port/path` or `https://...` in HTTP mode. |
| `-whitelist` | `WHITELIST` | Comma separated list of hostnames to get certificates for. Strongly recommended: if omitted, TLSproxy requests a certificate for any hostname a client asks for, which can be abused to exhaust your Let's Encrypt rate limits. |
| `-email` | `EMAIL` | Optional contact email for your Let's Encrypt account. |
| `-listen` | `LISTEN` | Address to listen on. Defaults to `0.0.0.0:443`. |
| `-http` | `HTTP` | `true` for HTTP proxying instead of TCP proxying. Defaults to `false`. |
| `-proxy` | `PROXY` | `true` to send a PROXY protocol v1 header to the backend (TCP mode only). Defaults to `false`. |
| `-mintls` | `MINTLS` | Minimum TLS version, `1.2` or `1.3`. Defaults to `1.2`. |
| `-certs` | `CERTS` | Directory where certificates are cached. Defaults to `certs`, in the working directory. |
| `-har` | `HAR` | `true` to record every request and response in HTTP mode, until you call `GET /downloadharfile`. This returns a JSON HTTP Archive (HAR) file, which you can open in your browser's dev tools to inspect each request. Anyone can download it, and it holds full bodies and cookies in memory: for development only. |
| `-debug` | `DEBUG` | `true` for more verbose logs about certificates. |

Boolean variables accept `true`, `1`, `false`, `0`, etc.

TLSproxy shuts down gracefully on `SIGINT` and `SIGTERM`.

## Roadmap

Next on the roadmap:

- use a store for shared certificates (Redis? other?)

## License etc.

You can do whatever you want with TLSproxy but you must assume full responsibility, ie. I'm not liable.

You can [hire me if you need professional support](https://hire.chris-hartwig.com).

Or make a Bitcoin donation to say "Thanks" :-)

![1A4ZNLXBYP8m1HL7RsCwHDU8Thuhx6YXcQ](./BTCtlsproxy.png)
