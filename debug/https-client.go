package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type zeroSource4 struct{}

func (zeroSource4) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

func main() {

	w := os.Stdout
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			Rand:         zeroSource4{},
			KeyLogWriter: w,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
		},
	}

	client := &http.Client{Transport: tr}
	resp, _ := client.Get("https://127.0.0.1:8443")

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(body))

}
