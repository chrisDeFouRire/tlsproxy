package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"path"

	"net/url"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var (
	// Tag is set by Gitlab's CI build process
	Tag string
	// Build is set by Gitlab's CI build process
	Build string
)
 
func main() {

	log.SetFlags(log.LUTC | log.LstdFlags)

	var email = flag.String("email", "", "email for let's encrypt account")
	var listen = flag.String("listen", "0.0.0.0:443", "address to listen to")
	var backend = flag.String("backend", "localhost:80", "address to send traffic to")
	var httpmode = flag.Bool("http", false, "if true, use HTTP proxy instead of TCP proxy")
	var proxyproto = flag.Bool("proxy", false, "if true, use the PROXY protocol for TCP proxying")
	var debug = flag.Bool("debug", false, "more verbose debug")
 
	flag.Parse()

	if envEmail := os.Getenv("EMAIL"); envEmail != "" {
		email = &envEmail
	}
	if envListen := os.Getenv("LISTEN"); envListen != "" {
		listen = &envListen
	}
	if envBackend := os.Getenv("BACKEND"); envBackend != "" {
		backend = &envBackend
	}
	if envHttpmode := os.Getenv("HTTP"); envHttpmode == "true" {
		*httpmode = true
	}
	if envProxyproto := os.Getenv("PROXY"); envProxyproto == "true" {
		*proxyproto = true
	}
	if envDebug := os.Getenv("DEBUG"); envDebug == "true" {
		*debug = true
	}

	if *email == "" {
		log.Fatal("You must specify an email sent to LetsEncrypt")
	}

	log.Printf("TLS proxy %s %s", Build, Tag)
	log.Print("Starting TLS proxy, on ", *listen)
	log.Print("Forwarding to ", *backend)
	log.Print("Using email: ", *email)
	log.Print("Using HTTP proxying: ", *httpmode)
	if !*httpmode {
		log.Print("Using PROXY protocol: ", *proxyproto)
	}
	log.Print("Using debug mode: ", *debug)

	var cache autocert.Cache = autocert.DirCache("certs")
	if *debug {
		cache = newDebugCache(cache)
	}

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: nil,
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
		MinVersion: tls.VersionTLS12,
		/*CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		 Specifying these cipherSuites breaks TLSproxy, but only for getting new certs, existing certs keep working
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},*/
		NextProtos: []string{acme.ALPNProto, "h2"},
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

		u, _ := url.Parse(*backend)
		if !strings.HasSuffix(u.Path, "/") {
			u.Path = u.Path + "/"
		}

		director := func(req *http.Request) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Hostname()
			req.URL.Path = path.Join(u.Path , req.URL.Path)
			if _, ok := req.Header["User-Agent"]; !ok {
				// explicitly disable User-Agent so it's not set to default value
				req.Header.Set("User-Agent", "")
			}
			req.Header.Set("X-Forwarded-Proto", "https")
		}
		proxy := &httputil.ReverseProxy{Director: director}

		fun := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			proxy.ServeHTTP(w, r)
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
