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
	fmt.Printf("%+v\n", ipheader)

	var tcp TCPHeader
	tcpheader := tcp.CreateSyn([]byte{0xa6, 0xe9}, []byte{0x30, 0x39})
	fmt.Printf("%+v\n", tcpheader)

	// https://milestone-of-se.nesuke.com/nw-basic/tcp-udp/tcp-option/
	tcpOptions := struct {
		MaxsSegmentSize []byte
		SackPermitted   []byte
		Timestamps      []byte
		NoOperation     []byte
		WindowScale     []byte
	}{
		// オプション番号2, Length, 値(2byte)
		MaxsSegmentSize: []byte{0x02, 0x04, 0x05, 0xb4},
		// オプション番号4, Length
		SackPermitted: []byte{0x04, 0x02},
		// オプション番号1
		NoOperation: []byte{0x01},
		// オプション番号3, Length, 値(1byte)
		WindowScale: []byte{0x03, 0x03, 0x07},
		// オプション番号8, Length, Timestamp value(4byte), echo reply(4byte)
		Timestamps: []byte{0x08, 0x10, 0x57, 0x4b, 0x85, 0xcf, 0x00, 0x00, 0x00, 0x00},
	}

	fmt.Printf("%+v\n", tcpOptions)
	fmt.Printf("%d\n", toByteLen(tcpheader))
	fmt.Printf("%d\n", toByteLen(tcpOptions))

}
