package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"os"

	"net/url"

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

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: nil,
		Cache:      autocert.DirCache("certs"),
		Email:      *email,
		ForceRSA:   true,
	}

	tlsconfig := &tls.Config{
		GetCertificate:           certManager.GetCertificate,
		PreferServerCipherSuites: true,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		/* Specifying these cipherSuites breaks TLSproxy, but only for getting new certs, existing certs keep working
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
	}

	// if not in http proxy mode, assume http/1.1 backend
	if !*httpmode {
		tlsconfig.NextProtos = []string{"http/1.1"}
	}

	listener, err := tls.Listen("tcp", *listen, tlsconfig)
	if err != nil {
		log.Println(err)
		return
	}
	defer listener.Close()

	if *httpmode { // HTTP proxy mode

		u, _ := url.Parse(*backend)

		director := func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = req.Host
			req.URL.Path = u.Path + "/" + req.URL.Path
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
