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
	var port uint16 = 8080

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

	req := tcpip.NewHttpGetRequest("/", "localhost:8080")
	pshack := tcpip.TCPIP{
		DestIP:    dest,
		DestPort:  port,
		TcpFlag:   "PSHACK",
		SeqNumber: ack.SeqNumber,
		AckNumber: ack.AckNumber,
		Data:      req.ReqtoByteArr(req),
	}
	tcpip.SendToNginx(sendfd, pshack)
}
