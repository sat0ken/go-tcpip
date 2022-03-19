package main

import (
	"fmt"
	"log"
	"syscall"
)

func ThreewayHandShake(tcpip TCPIP) {

	synPacket := NewTCPIP(tcpip)

	destIp := iptobyte(tcpip.DestIP)
	destPort := uintTo2byte(tcpip.DestPort)
	addr := syscall.SockaddrInet4{
		Addr: [4]byte{destIp[0], destIp[1], destIp[2], destIp[3]},
		Port: int(tcpip.DestPort),
	}

	sendfd := NewSocket(syscall.AF_INET, syscall.IPPROTO_TCP)
	err := SocketSend(sendfd, synPacket, addr)
	if err != nil {
		log.Fatalf("Send SYN packet err : %v\n", err)
	}

	chanpacket := make(chan TCPHeader)
	SocketRecvfrom(sendfd, destIp, destPort, chanpacket)
	synack := <-chanpacket
	fmt.Printf("main %+v\n", synack)

	switch synack.ControlFlags {
	case []byte{0x12}:
		ack := TCPIP{
			DestIP:    tcpip.DestIP,
			DestPort:  tcpip.DestPort,
			TcpFlag:   "ACK",
			SeqNumber: synack.AcknowlegeNumber,
			AckNumber: []byte{0x00, 0x00, 0x00, 0x01},
		}
		ackPacket := NewTCPIP(ack)
		err = SocketSend(sendfd, ackPacket, addr)
	}

	syscall.Close(sendfd)
}
