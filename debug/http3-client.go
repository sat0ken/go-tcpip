package main

import (
	"crypto/tls"
	"fmt"
	"github.com/lucas-clemente/quic-go/http3"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"tcpip/debug/utils"
)

func main() {

	w := os.Stdout
	r := http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			MaxVersion:         tls.VersionTLS13,
			Rand:               utils.ZeroSource{},
			KeyLogWriter:       w,
			InsecureSkipVerify: true,
		},
	}
    req, _ := http.NewRequest("GET", "https://127.0.0.1:18443", nil)
	//req, _ := http.NewRequest("GET", "https://142.251.42.174", nil)

	resp, err := r.RoundTrip(req)
	if err != nil {
		log.Fatal(err)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Print(string(body))

}
