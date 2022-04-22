package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
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

// https://www.ipa.go.jp/security/rfc/RFC5246-08JA.html
func randomByte(num int) []byte {
	b := make([]byte, num)
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

func noRandomByte(length int) []byte {
	b := make([]byte, length)
	for i := 0; i < length; i++ {
		b[i] = 0x00
	}
	return b
}

func getNonce(i int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(i))
	return b
}

func strtoByte(str string) []byte {
	b, _ := hex.DecodeString(str)
	return b
}

func readClientCertificate() tls.Certificate {
	cert, err := tls.LoadX509KeyPair("debug/client.pem", "debug/client-key.pem")
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

// zeroSource is an io.Reader that returns an unlimited number of zero bytes.
type zeroSource struct{}

func (zeroSource) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}
