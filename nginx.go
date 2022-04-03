package main

import (
	"fmt"
	"log"
	"syscall"
	"time"
)

func synack_finack() {
	dest := "127.0.0.1"
	var port uint16 = 8443

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

	//req := NewHttpGetRequest("/", "localhost:8080")
	//pshack := TCPIP{
	//	DestIP:    localip,
	//	DestPort:  port,
	//	TcpFlag:   "PSHACK",
	//	SeqNumber: ack.SeqNumber,
	//	AckNumber: ack.AckNumber,
	//	Data:      req.reqtoByteArr(req),
	//}
	//startTCPConnection(sendfd, pshack)

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

func nginx() {
	localip := "127.0.0.1"
	var port uint16 = 8080

	syn := TCPIP{
		DestIP:   localip,
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

	req := NewHttpGetRequest("/", "localhost:8080")
	pshack := TCPIP{
		DestIP:    localip,
		DestPort:  port,
		TcpFlag:   "PSHACK",
		SeqNumber: ack.SeqNumber,
		AckNumber: ack.AckNumber,
		Data:      req.reqtoByteArr(req),
	}
	sendNginx(sendfd, pshack)
}
