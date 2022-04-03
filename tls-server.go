package main

import (
	"bufio"
	"crypto/tls"
	"log"
	"net"
)

// https://gist.github.com/denji/12b3a568f092ab951456
func main() {
	cert, err := tls.LoadX509KeyPair("certs/my-tls.pem", "certs/my-tls-key.pem")
	if err != nil {
		log.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", ":10443", config)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		log.Printf("Client From : %v\n", conn.RemoteAddr())
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		_, err := r.ReadString('\n')
		if err != nil {
			//log.Println(err)
			return
		}
		//fmt.Println(msg)
	}
}
