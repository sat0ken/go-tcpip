package main

import (
	"fmt"
	"log"
	"syscall"
	"time"
)

func main() {
	dest := "147.75.40.148"
	var port uint16 = 443

	syn := TCPIP{
		DestIP:   dest,
		DestPort: port,
		TcpFlag:  "SYN",
	}
	sendfd := NewTCPSocket()
	defer syscall.Close(sendfd)
	ack, err := startTCPConnection(sendfd, syn)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("TCP Connection is success!!\n")
	time.Sleep(10 * time.Millisecond)

	fin := TCPIP{
		DestIP:    dest,
		DestPort:  port,
		TcpFlag:   "FINACK",
		SeqNumber: ack.SeqNumber,
		AckNumber: ack.AckNumber,
	}
	_, err = startTCPConnection(sendfd, fin)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("TCP Connection Close is success!!\n")
}
