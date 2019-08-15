package main

import (
	"crypto/tls"
	"flag"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"strings"
	"time"

	"net/url"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	//"github.com/alecthomas/repr"
)

func main() {

	log.SetFlags(log.LUTC | log.LstdFlags)

	var hostname = flag.String("hostname", os.Getenv("HOSTNAME"), "hostname for TLS certificate")
	var email = flag.String("email", os.Getenv("EMAIL"), "email for let's encrypt account")
	var listen = flag.String("listen", os.Getenv("LISTEN"), "address to listen to")
	var backend = flag.String("backend", os.Getenv("BACKEND"), "address to send traffic to")
	var httpmode = flag.Bool("http", os.Getenv("HTTP") == "true", "if true, use HTTP proxy instead of TCP proxy")
	var proxyproto = flag.Bool("proxy", os.Getenv("PROXY") == "true", "if true, use the PROXY protocol for TCP proxying")
	var har = flag.Bool("har", os.Getenv("HAR") == "true", "if true and HTTP mode is used, allow to download an HAR file")
	var debug = flag.Bool("debug", os.Getenv("DEBUG") == "true", "more verbose debug")

	flag.Parse()

	if *listen == "" {
		*listen = "0.0.0.0:443"
	}

	if *backend == "" {
		log.Fatal("You must specify a backend as a host:port (tcp proxy) or a url (http proxy)")
	}
	if *email == "" {
		log.Fatal("You must specify an email sent to LetsEncrypt")
	}

	log.Print("Starting TLS proxy, on ", *listen)
	log.Print("Forwarding to ", *backend)
	log.Print("Using email: ", *email)
	log.Print("Using HTTP proxying: ", *httpmode)
	log.Print("Installing HAR HTTP endpoint: ", *har)
	if !*httpmode {
		log.Print("Using PROXY protocol: ", *proxyproto)
	}
	log.Print("Using debug mode: ", *debug)

	var cache autocert.Cache = autocert.DirCache("certs")
	if *debug {
		cache = newDebugCache(cache)
	}

	var hostPolicy autocert.HostPolicy
	if *hostname != "" {
		hostPolicy = autocert.HostWhitelist(*hostname)
	}

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: hostPolicy,
		Cache:      cache,
		Email:      *email,
		ForceRSA:   true,
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

	tlsconfig := &tls.Config{
		GetCertificate:           getCertificate,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		NextProtos:               []string{acme.ALPNProto, "h2"},
	}

	// if not in http proxy mode, assume http/1.1 backend
	if !*httpmode {
		tlsconfig.NextProtos = []string{acme.ALPNProto, "http/1.1"}
	}

	listener, err := tls.Listen("tcp", *listen, tlsconfig)
	if err != nil {
		log.Println(err)
		return
	}
	defer listener.Close()

	if *httpmode { // HTTP proxy mode

		harLog := newHarLog()

		u, _ := url.Parse(*backend)
		if !strings.HasSuffix(u.Path, "/") {
			u.Path = u.Path + "/"
		}

		director := func(req *http.Request) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			req.URL.Path = path.Join(u.Path, req.URL.Path)
			if _, ok := req.Header["User-Agent"]; !ok {
				// explicitly disable User-Agent so it's not set to default value
				req.Header.Set("User-Agent", "")
			}
			req.Header.Set("X-Forwarded-Proto", "https")
		}
		proxy := &httputil.ReverseProxy{Director: director}

		fun := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !*har {
				proxy.ServeHTTP(w, r)
				return
			}

			if r.Method == http.MethodGet && r.URL.RequestURI() == "/downloadharfile" {
				har := Har{}
				har.HarLog = *harLog		
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Disposition", "attachment; filename=\"tlsproxy.har\"")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(har)
				harLog = newHarLog()
				return
			}

			harEntry := new(HarEntry)
			fillIPAddress(r, harEntry)
			start := time.Now()
			harReq := parseRequest(r)
			wp := NewResponseWriterProxy(w)

			proxy.ServeHTTP(wp, r)

			end := time.Now()
			harRes := wp.GetResponse()
			harEntry.Request = harReq
			harEntry.StartedDateTime = start
			harEntry.Response = harRes
			harEntry.Time = end.Sub(start).Nanoseconds() / 1e6

			harLog.addEntry(*harEntry)
		})

		log.Fatal(http.Serve(listener, fun))
		return
	}

	// TCP mode, accept a connection and forward it

	for {
		conn, err := listener.Accept()

		if err != nil {
			log.Println(err)
			continue
		}
		go forward(*backend, conn, *proxyproto)
	}
}
