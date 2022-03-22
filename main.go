package main

import (
	"fmt"
	"log"
	"syscall"
	"time"
)

func main() {
	dest := "13.114.40.48"
	var port uint16 = 443

	syn := TCPIP{
		DestIP:   dest,
		DestPort: port,
		TcpFlag:  "SYN",
	}
	sendfd := NewTCPSocket()
	defer syscall.Close(sendfd)
	fmt.Printf("Send SYN packet to %s\n", dest)
	ack, err := startTCPConnection(sendfd, syn)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("TCP Connection is success!!\n\n")
	time.Sleep(10 * time.Millisecond)

	clienthello := TCPIP{
		DestIP:    dest,
		DestPort:  port,
		TcpFlag:   "PSHACK",
		SeqNumber: ack.SeqNumber,
		AckNumber: ack.AckNumber,
		Data:      NewClientHello(),
	}
	serverhello, err := startTLSHandshake(sendfd, clienthello)
	if err != nil {
		log.Fatal(err)
	}

	fin := TCPIP{
		DestIP:    dest,
		DestPort:  port,
		TcpFlag:   "FINACK",
		SeqNumber: serverhello.SequenceNumber,
		AckNumber: serverhello.AcknowlegeNumber,
	}
	fmt.Printf("Send FINACK packet to %s\n", dest)
	_, err = startTCPConnection(sendfd, fin)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("TCP Connection Close is success!!\n")
}
