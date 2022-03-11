package main

import (
	"fmt"
	"log"
)

func main() {
	localmac := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	_ = localmac

	localif, err := getLocalIpAddr("lo")
	if err != nil {
		log.Fatalf("getLocalIpAddr err : %v", err)
	}
	//fmt.Printf("%+v\n", localif)
	var ip IPHeader
	ipheader := ip.Create(localif.LocalIpAddr, localif.LocalIpAddr, "TCP")

	var tcp TCPHeader
	tcpheader := tcp.CreateSyn([]byte{0xa6, 0xe9}, []byte{0x30, 0x39})

	tcpOptions := struct {
		MaxSize       []byte
		SackPermitted []byte
		Timestamps    []byte
		NoOperation   []byte
		WindowScale   []byte
	}{
		SackPermitted: []byte{0x04, 0x02},
		NoOperation:   []byte{0x01},
		WindowScale:   []byte{0x03, 0x03, 0x07},
	}
	
	fmt.Printf("%+v\n", ip)

}
