package main

import (
	"crypto/tls"
	"fmt"
	"golang.org/x/net/http2"
	"log"
	"net/http"
	"os"

	"tcpip/debug/utils"
)

// https://github.com/denji/golang-tls
func HelloHTTP2Server(w http.ResponseWriter, req *http.Request) {
	fmt.Printf("client from : %s\n", req.RemoteAddr)
	fmt.Fprintf(w, "hello\n")
	//w.Header().Set("Content-Type", "text/plain")
	//w.Write([]byte(`hello https server`))
	//w.Write([]byte("\n"))
}

func main() {
	http.HandleFunc("/", HelloHTTP2Server)

	w := os.Stdout
	server := &http.Server{
		Addr: ":18443",
		TLSConfig: &tls.Config{
			Rand:         utils.ZeroSource{}, // for example only; don't do this.
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			KeyLogWriter: w,
		},
	}

	http2.ConfigureServer(server, nil)

	err := server.ListenAndServeTLS("./my-tls.pem", "./my-tls-key.pem")
	if err != nil {
		log.Fatal(err)
	}
}
