package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	handshakeTimeout = 10 * time.Second
	dialTimeout      = 10 * time.Second
	// once one direction of a proxied connection is finished, the other one
	// gets this long to drain before the connection is torn down
	drainTimeout = 30 * time.Second
)

// proxyHeader builds a PROXY protocol v1 header describing a connection
// from src to dst.
func proxyHeader(src, dst net.Addr) string {
	s, sok := src.(*net.TCPAddr)
	d, dok := dst.(*net.TCPAddr)
	if !sok || !dok {
		return "PROXY UNKNOWN\r\n"
	}
	if s4, d4 := s.IP.To4(), d.IP.To4(); s4 != nil && d4 != nil {
		return fmt.Sprintf("PROXY TCP4 %s %s %d %d\r\n", s4, d4, s.Port, d.Port)
	}
	if s.IP.To4() == nil && d.IP.To4() == nil && s.IP.To16() != nil && d.IP.To16() != nil {
		return fmt.Sprintf("PROXY TCP6 %s %s %d %d\r\n", s.IP, d.IP, s.Port, d.Port)
	}
	// mixed address families can't be expressed in a v1 header
	return "PROXY UNKNOWN\r\n"
}

// forward completes the TLS handshake on conn, then pipes the decrypted
// stream to backendHostport until either side is done.
func forward(backendHostport string, conn net.Conn, proxyproto bool) {
	defer conn.Close()

	if tlsConn, ok := conn.(*tls.Conn); ok {
		ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
		err := tlsConn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			log.Printf("TLS handshake with %s failed: %v", conn.RemoteAddr(), err)
			return
		}
		if tlsConn.ConnectionState().NegotiatedProtocol == acme.ALPNProto {
			// tls-alpn-01 challenge from the ACME server, the handshake was all it needed
			return
		}
	}

	backend, err := net.DialTimeout("tcp", backendHostport, dialTimeout)
	if err != nil {
		log.Printf("Dial failed: %v", err)
		return
	}
	defer backend.Close()

	if proxyproto {
		if _, err := io.WriteString(backend, proxyHeader(conn.RemoteAddr(), conn.LocalAddr())); err != nil {
			log.Printf("Writing PROXY header failed: %v", err)
			return
		}
	}

	done := make(chan struct{}, 2)
	go pipe(backend, conn, done)
	go pipe(conn, backend, done)

	<-done
	deadline := time.Now().Add(drainTimeout)
	conn.SetDeadline(deadline)
	backend.SetDeadline(deadline)
	<-done
}

type closeWriter interface {
	CloseWrite() error
}

// pipe copies src to dst, then half-closes dst so the peer sees EOF.
func pipe(dst, src net.Conn, done chan<- struct{}) {
	io.Copy(dst, src)
	if cw, ok := dst.(closeWriter); ok {
		cw.CloseWrite()
	} else {
		dst.Close()
	}
	done <- struct{}{}
}
