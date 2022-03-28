package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"math/rand"
	"net"
)

type LocalIpMacAddr struct {
	LocalMacAddr []byte
	LocalIpAddr  []byte
	Index        int
}

// ローカルのmacアドレスとIPを返す
func getLocalIpAddr(ifname string) (localif LocalIpMacAddr, err error) {
	nif, err := net.InterfaceByName(ifname)
	if err != nil {
		return localif, err
	}
	localif.LocalMacAddr = nif.HardwareAddr
	localif.Index = nif.Index

	addrs, err := nif.Addrs()
	if err != nil {
		return localif, err
	}
	for _, addr := range addrs {
		//if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.To4() != nil {
				localif.LocalIpAddr = ipnet.IP.To4()
			}
		}
	}

	return localif, nil
}

// TLSのClientHelloで32byteの乱数をセット
func random32byte() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

// クライアント側で利用可能な暗号スイートのリストを返す
func getChipersList() []byte {

	var b []byte

	// https://pkg.go.dev/crypto/tls#CipherSuites
	cipher := tls.CipherSuites()
	for _, v := range cipher {
		b = append(b, uintTo2byte(v.ID)...)
	}

	return b
}

func readByteNum(packet []byte, offset, n int64) []byte {
	r := bytes.NewReader(packet)
	sr := io.NewSectionReader(r, offset, n)

	buf := make([]byte, n)
	_, err := sr.Read(buf)
	if err != nil {
		log.Fatalf("read byte err : %v\n", err)
	}

	return buf
}
