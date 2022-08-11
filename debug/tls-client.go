package main

import (
	"crypto/hacktls"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"tcpip/debug/utils"
)

func main() {
	w := os.Stdout
	config := &tls.Config{
		//Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Rand:         utils.ZeroSource{},
		KeyLogWriter: w,
		// 楕円曲線のタイプをP256に設定
		// CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveID(tls2.X25519)},
		CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256},
		//CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	conn, err := tls.Dial("tcp", "127.0.0.1:8443", config)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	req, _ := hex.DecodeString("474554202f20485454502f312e310d0a486f73743a203132372e302e302e313a31303434330d0a557365722d4167656e743a206375726c2f372e36382e300d0a4163636570743a202a2f2a0d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a")
	//n, err := conn.Write([]byte("hello\n"))
	n, err := conn.Write(req)
	//n, err := conn.Write(req)
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
