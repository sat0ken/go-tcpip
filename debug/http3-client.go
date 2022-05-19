package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"io"
	"log"
	"os"
	"tcpip/debug/utils"
)

func main() {
	w := os.Stdout
	tlsConf := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Rand:         utils.ZeroSource{},
		NextProtos:   []string{"quic-echo-example"},
		KeyLogWriter: w,
	}

	conn, err := quic.DialAddr("localhost:18443", tlsConf, nil)
	if err != nil {
		log.Fatal(err)
	}

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	message := []byte(`hello`)

	stream.Write(message)

	buf := make([]byte, len(message))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Message from server : %s\n", string(buf))
}
