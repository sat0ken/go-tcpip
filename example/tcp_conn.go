package main

import (
	"fmt"
	"log"
	"syscall"
	"tcpip"
	"time"
)

func main() {
	dest := "127.0.0.1"
	var port uint16 = 8443

	syn := tcpip.TCPIP{
		DestIP:   dest,
		DestPort: port,
		TcpFlag:  "SYN",
	}

	sendfd := tcpip.NewTCPSocket()
	defer syscall.Close(sendfd)
	ack, err := tcpip.StartTCPConnection(sendfd, syn)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("TCP Connection is success!!\n")
	time.Sleep(10 * time.Millisecond)

	fin := tcpip.TCPIP{
		DestIP:    dest,
		DestPort:  port,
		TcpFlag:   "FINACK",
		SeqNumber: ack.SeqNumber,
		AckNumber: ack.AckNumber,
	}
	_, err = tcpip.StartTCPConnection(sendfd, fin)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("TCP Connection Close is success!!\n")
}
