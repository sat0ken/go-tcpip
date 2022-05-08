package main

import (
	"crypto/tls"
	"fmt"
	"golang.org/x/net/http2"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"tcpip/debug/utils"
)

func main() {

	w := os.Stdout
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			Rand:         utils.ZeroSource{},
			KeyLogWriter: w,
		},
	}

	client := &http.Client{Transport: tr}
	resp, _ := client.Get("https://127.0.0.1:18443")

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(string(body))

}
