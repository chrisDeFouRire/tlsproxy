package main

import (
	"io"
	"log"
	"net"
)

func forward(backend string, conn net.Conn) {
	client, err := net.Dial("tcp", backend)
	if err != nil {
		log.Printf("Dial failed: %v", err)
		conn.Close()
		return
	}
	go func() {
		defer client.Close()
		defer conn.Close()
		io.Copy(client, conn)
	}()
	go func() {
		defer client.Close()
		defer conn.Close()
		io.Copy(conn, client)
	}()
}
