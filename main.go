package main

import (
	"fmt"
	"log"
	"syscall"
	"time"
)

func main() {
	udpSend()
}

func arp() {
	localif, err := getLocalIpAddr("wlp4s0")
	if err != nil {
		log.Fatalf("getLocalIpAddr err : %v", err)
	}

	ethernet := NewEthernet([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, localif.LocalMacAddr, "ARP")
	//ethernet := NewEthernet([]byte{0x1c, 0x3b, 0xf3, 0x95, 0x6a, 0x2c}, localif.LocalMacAddr, "ARP")
	arpReq := NewArpRequest(localif, "192.168.0.17")

	var sendArp []byte
	sendArp = append(sendArp, toByteArr(ethernet)...)
	sendArp = append(sendArp, toByteArr(arpReq)...)

	arpreply := arpReq.Send(localif.Index, sendArp)
	fmt.Printf("ARP Reply : %s\n", printByteArr(arpreply.SenderMacAddr))
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
	_ = ack
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("TCP Connection is success!!\n")
	time.Sleep(10 * time.Millisecond)

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
	sendNginx(sendfd, pshack)

}
