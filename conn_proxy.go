package main

import (
	"io"
	"log"
	"net"
)

func forward(conn net.Conn) {
	client, err := net.Dial("tcp", "localhost:80")
	if err != nil {
		log.Printf("Dial failed: %v", err)
		conn.Close()
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
