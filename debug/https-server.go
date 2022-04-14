package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
)

type zeroSource3 struct{}

func (zeroSource3) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

// https://github.com/denji/golang-tls
func HelloServer(w http.ResponseWriter, req *http.Request) {
	fmt.Printf("client from : %s\n", req.RemoteAddr)
	fmt.Fprintf(w, "hello\n")
	//w.Header().Set("Content-Type", "text/plain")
	//w.Write([]byte(`hello https server`))
	//w.Write([]byte("\n"))
}

func main() {
	http.HandleFunc("/", HelloServer)

	w := os.Stdout
	server := &http.Server{
		Addr: ":10443",
		TLSConfig: &tls.Config{
			Rand:         zeroSource3{}, // for example only; don't do this.
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			KeyLogWriter: w,
		},
	}

	err := server.ListenAndServeTLS("./my-tls.pem", "./my-tls-key.pem")
	if err != nil {
		log.Fatal(err)
	}
}
