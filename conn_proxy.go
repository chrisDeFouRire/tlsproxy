package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
)

func split(addr net.Addr) (string, string, error) {
	tmp := strings.Split(addr.String(), ":")
	ip := net.ParseIP(tmp[0]).To4()
	if ip == nil {
		return "", "", fmt.Errorf("source address %s is not a tcp4 IP", tmp[0])
	}
	return ip.String(), tmp[1], nil
}

func forward(backendHostport string, conn net.Conn, proxyproto bool) {
	backend, err := net.Dial("tcp", backendHostport)
	if err != nil {
		log.Printf("Dial failed: %v", err)
		conn.Close()
		return
	}
	if proxyproto {
		tcpversion := "TCP4"
		srcaddr, srcport, srcerr := split(conn.RemoteAddr())
		dstaddr, dstport, _ := split(conn.LocalAddr())
		if srcerr != nil { // source address is not tcp4
			log.Print("address is not TCPv4 ", conn.RemoteAddr())
			conn.Close()
			return
		}
		proxyheader := fmt.Sprintf("PROXY %s %s %s %s %s\r\n", tcpversion, srcaddr, dstaddr, srcport, dstport)
		backend.Write([]byte(proxyheader))
	}
	go func() {
		defer backend.Close()
		defer conn.Close()
		io.Copy(backend, conn)
	}()
	go func() {
		defer backend.Close()
		defer conn.Close()
		io.Copy(conn, backend)
	}()
}
