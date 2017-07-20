package main

import (
	"crypto/tls"
	"flag"
	"log"
	"os"

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

	if *email == "" {
		log.Fatal("You must specify an email sent to LetsEncrypt")
	}

	log.Printf("TLS proxy %s %s", Build, Tag)
	log.Print("Starting TLS proxy, on ", *listen)
	log.Print("Forwarding to ", *backend)
	log.Print("Using email: ", *email)

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: nil,
		Cache:      autocert.DirCache("certs"),
		Email:      *email,
		ForceRSA:   true,
	}

	tlsconfig := &tls.Config{
		GetCertificate: certManager.GetCertificate,
	}

	listener, err := tls.Listen("tcp", *listen, tlsconfig)
	if err != nil {
		log.Println(err)
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()

		if err != nil {
			log.Println(err)
			continue
		}
		go forward(conn)
	}
}
