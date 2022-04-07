package main

import (
	"crypto/tls"
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
		MaxVersion:   tls.VersionTLS12,
		Rand:         zeroSource2{},
		KeyLogWriter: w,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
	}
	client, err := tls.Dial("tcp", "127.0.0.1:10443", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
}
