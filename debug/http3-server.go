package main

import (
	"crypto/tls"
	"fmt"
	"github.com/lucas-clemente/quic-go/http3"
	"log"
	"net/http"
	"os"

	"tcpip/debug/utils"
)

func HelloHTTP3Server(w http.ResponseWriter, req *http.Request) {
	fmt.Printf("client from : %s\n", req.RemoteAddr)
	fmt.Fprintf(w, "hello\n")
}

func main() {

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(HelloHTTP3Server))

	w := os.Stdout
	tlsCert, err := tls.LoadX509KeyPair("./my-tls.pem", "./my-tls-key.pem")
	if err != nil {
		log.Fatalf("Load key pair is err %v\n", err)
	}

	server := http3.Server{
		Addr: "127.0.0.1:18443",
		//Port: 18843,
		TLSConfig: &tls.Config{
			Rand:         utils.ZeroSource{},
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			NextProtos:   []string{"quic-echo-example"},
			KeyLogWriter: w,
		},
		Handler: mux,
	}

	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
