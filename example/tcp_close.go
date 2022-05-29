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
	var port uint16 = 22

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
	fmt.Println("TCP Connection is success!!")
	time.Sleep(10 * time.Millisecond)

	fin := tcpip.TCPIP{
		DestIP:    dest,
		DestPort:  port,
		TcpFlag:   "PSHACK",
		SeqNumber: ack.SeqNumber,
		AckNumber: ack.AckNumber,
		Data:      tcpip.StrtoByte("\n"),
	}
	pshPacket := tcpip.NewTCPIP(fin)
	destIp := tcpip.Iptobyte(fin.DestIP)
	addr := tcpip.SetSockAddrInet4(destIp, int(fin.DestPort))

	// 改行コードをSSHサーバに送ってConnectionをClose
	err = tcpip.SendIPv4Socket(sendfd, pshPacket, addr)
	if err != nil {
		log.Fatalf("Send PSH packet err : %v\n", err)
	}
	fmt.Println("TCP Connection close is success !!")
}
