package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const version = "3.0"

func envBool(name string) bool {
	b, _ := strconv.ParseBool(os.Getenv(name))
	return b
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func main() {
	log.SetFlags(log.LUTC | log.LstdFlags)

	var whitelist = flag.String("whitelist", os.Getenv("WHITELIST"), "whitelist of comma separated host names for TLS certificates")
	var email = flag.String("email", os.Getenv("EMAIL"), "optional contact email for the Let's Encrypt account")
	var listen = flag.String("listen", envOr("LISTEN", "0.0.0.0:443"), "address to listen to")
	var backend = flag.String("backend", os.Getenv("BACKEND"), "address to send traffic to: host:port (TCP proxy) or a URL (HTTP proxy)")
	var httpmode = flag.Bool("http", envBool("HTTP"), "if true, use HTTP proxy instead of TCP proxy")
	var proxyproto = flag.Bool("proxy", envBool("PROXY"), "if true, use the PROXY protocol for TCP proxying")
	var har = flag.Bool("har", envBool("HAR"), "if true and HTTP mode is used, allow to download an HAR file")
	var certsDir = flag.String("certs", envOr("CERTS", "certs"), "directory where certificates are cached")
	var minTLS = flag.String("mintls", envOr("MINTLS", "1.2"), "minimum TLS version: 1.2 or 1.3")
	var debug = flag.Bool("debug", envBool("DEBUG"), "more verbose debug")

	flag.Parse()

	minVersion, err := parseTLSVersion(*minTLS)
	if err != nil {
		log.Fatal(err)
	}

	if *backend == "" {
		log.Fatal("You must specify a backend as a host:port (tcp proxy) or a url (http proxy)")
	}
	var backendURL *url.URL
	if *httpmode {
		if backendURL, err = parseBackendURL(*backend); err != nil {
			log.Fatal(err)
		}
	} else if err := checkHostPort(*backend); err != nil {
		log.Fatal(err)
	}

	log.Print("Starting TLS proxy ", version, ", on ", *listen)
	log.Print("Forwarding to ", *backend)
	log.Print("Using email: ", *email)
	log.Print("Using HTTP proxying: ", *httpmode)
	if *httpmode {
		log.Print("Installing HAR HTTP endpoint: ", *har)
	} else {
		log.Print("Using PROXY protocol: ", *proxyproto)
	}
	log.Print("Minimum TLS version: ", *minTLS)
	log.Print("Caching certificates in: ", *certsDir)
	log.Print("Using debug mode: ", *debug)

	var cache autocert.Cache = autocert.DirCache(*certsDir)
	if *debug {
		cache = newDebugCache(cache)
	}

	var hostPolicy autocert.HostPolicy
	if hostnames := splitHostnames(*whitelist); len(hostnames) > 0 {
		log.Print("Allowed hostnames: ", strings.Join(hostnames, ", "))
		hostPolicy = autocert.HostWhitelist(hostnames...)
	} else {
		log.Print("WARNING: no whitelist, a certificate will be requested for any hostname clients ask for")
	}

	certManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: hostPolicy,
		Cache:      cache,
		Email:      *email,
	}

	getCertificate := certManager.GetCertificate
	if *debug {
		getCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			res, err := certManager.GetCertificate(hello)
			log.Printf("Getting cert for %s", hello.ServerName)
			if err != nil {
				log.Print("GetCertificate debug: ", err)
			}
			return res, err
		}
	}

	// in TCP mode, assume an http/1.1 backend
	nextProtos := []string{"http/1.1"}
	if *httpmode {
		nextProtos = []string{"h2", "http/1.1"}
	}
	tlsconfig := newTLSConfig(getCertificate, minVersion, nextProtos)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	listener := tls.NewListener(ln, tlsconfig)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *httpmode {
		var handler http.Handler = newReverseProxy(backendURL)
		if *har {
			log.Print("WARNING: HAR recording is on, anyone can download the recorded traffic from ", harDownloadPath)
			handler = newHarRecorder().handler(handler)
		}
		srv := &http.Server{
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
		}
		go func() {
			<-ctx.Done()
			log.Print("Shutting down")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			srv.Shutdown(shutdownCtx)
		}()
		if err := srv.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
		return
	}

	// TCP mode, accept a connection and forward it
	go func() {
		<-ctx.Done()
		log.Print("Shutting down")
		listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Println(err)
			time.Sleep(100 * time.Millisecond) // don't spin on persistent errors (eg. too many open files)
			continue
		}
		go forward(*backend, conn, *proxyproto)
	}
}

// newTLSConfig returns a modern TLS server configuration: TLS 1.3 (and
// optionally TLS 1.2 with Go's default AEAD-only ECDHE cipher suites), with
// the hybrid post-quantum key exchanges, which crypto/tls prefers over the
// classical ones. Listing them explicitly keeps them on even if a GODEBUG
// setting would turn them off.
func newTLSConfig(getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), minVersion uint16, nextProtos []string) *tls.Config {
	return &tls.Config{
		GetCertificate: getCertificate,
		MinVersion:     minVersion,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.SecP256r1MLKEM768,
			tls.SecP384r1MLKEM1024,
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		// acme-tls/1 lets autocert answer tls-alpn-01 challenges
		NextProtos: append(nextProtos, acme.ALPNProto),
	}
}

func parseTLSVersion(v string) (uint16, error) {
	switch strings.TrimSpace(v) {
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("invalid minimum TLS version %q, must be 1.2 or 1.3", v)
}

func parseBackendURL(backend string) (*url.URL, error) {
	u, err := url.Parse(backend)
	if err != nil {
		return nil, fmt.Errorf("invalid backend URL %q: %w", backend, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid backend URL %q, expected http://host:port or https://host:port", backend)
	}
	return u, nil
}

func checkHostPort(backend string) error {
	host, port, err := net.SplitHostPort(backend)
	if err == nil && host != "" && !strings.Contains(backend, "/") {
		if _, err = strconv.ParseUint(port, 10, 16); err == nil {
			return nil
		}
	}
	return fmt.Errorf("invalid TCP backend %q, expected host:port (use -http=true for a URL backend)", backend)
}

func splitHostnames(list string) []string {
	var hostnames []string
	for _, h := range strings.Split(list, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hostnames = append(hostnames, h)
		}
	}
	return hostnames
}

// newReverseProxy forwards requests to target, keeping the client's Host
// header so name based virtual hosts keep working on the backend.
func newReverseProxy(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host
			r.SetXForwarded()
		},
	}
}
