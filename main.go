package main

import (
	"crypto/tls"
	"flag"
	"log"

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

	flag.Parse()
	log.Printf("TLS proxy %s %s", Build, Tag)
	log.Print("Starting TLS proxy, on 0.0.0.0:443")
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: nil,
		Cache:      autocert.DirCache("certs"),
		Email:      *email,
		ForceRSA:   true,
	}

	tlsconfig := &tls.Config{GetCertificate: certManager.GetCertificate}

	listener, err := tls.Listen("tcp", ":443", tlsconfig)
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
