package main

import (
	"syscall"
	"time"
)

func main() {
	localip := "127.0.0.1"
	var port uint16 = 8080

	syn := TCPIP{
		DestIP:   localip,
		DestPort: port,
		TcpFlag:  "SYN",
	}

	sendfd := NewSocket(syscall.AF_INET, syscall.IPPROTO_TCP)
	defer syscall.Close(sendfd)
	ack := startConnection(sendfd, syn)
	time.Sleep(100 * time.Millisecond)

	var req HttpRequest
	req = req.NewGetRequest("/", "localhost:8080")
	pshack := TCPIP{
		DestIP:    localip,
		DestPort:  port,
		TcpFlag:   "PSHACK",
		SeqNumber: ack.SeqNumber,
		AckNumber: ack.AckNumber,
		Data:      req.reqtoByteArr(req),
	}
	sendToNginx(sendfd, pshack)

}
