package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"tcpip/debug/utils"
)

func main() {

	w := os.Stdout
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			Rand:         utils.ZeroSource{},
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
