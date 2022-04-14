package main

import (
	"crypto/hacktls"
	"fmt"
	"log"
	"os"
)

type zeroSource2 struct{}

func (zeroSource2) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

func main() {
	w := os.Stdout
	config := &tls.Config{
		//Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		Rand:         zeroSource2{},
		KeyLogWriter: w,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
	}
	conn, err := tls.Dial("tcp", "127.0.0.1:10443", config)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	n, err := conn.Write([]byte("hello\n"))
	if err != nil {
		log.Println(n, err)
		return
	}

	buf := make([]byte, 500)
	n, err = conn.Read(buf)
	if err != nil {
		log.Println(n, err)
		return
	}

	fmt.Printf("message from server : %s\n", string(buf[:n]))

}
