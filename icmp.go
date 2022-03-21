package main

import (
	"fmt"
	"log"
	"syscall"
)

type ICMP struct {
	Type           []byte
	Code           []byte
	CheckSum       []byte
	Identification []byte
	SequenceNumber []byte
	Data           []byte
}

func NewICMP() ICMP {
	// https://www.infraexpert.com/study/tcpip4.html
	icmp := ICMP{
		// ping request
		Type:           []byte{0x08},
		Code:           []byte{0x00},
		CheckSum:       []byte{0x00, 0x00},
		Identification: []byte{0x00, 0x10},
		SequenceNumber: []byte{0x00, 0x01},
		Data:           []byte{0x01, 0x02},
	}

	icmpsum := sumByteArr(toByteArr(icmp))
	icmp.CheckSum = checksum(icmpsum)

	return icmp
}

func (*ICMP) Send(ifindex int, packet []byte) ICMP {
	addr := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_IP,
		Ifindex:  ifindex,
	}

	sendfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("create icmp sendfd err : %v\n", err)
	}

	err = syscall.Sendto(sendfd, packet, 0, &addr)
	if err != nil {
		log.Fatalf("Send to err : %v\n", err)
	}
	fmt.Println("send icmp packet")

	for {
		recvBuf := make([]byte, 1500)
		_, _, err := syscall.Recvfrom(sendfd, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// IPヘッダのProtocolがICMPであることをチェック
		if recvBuf[23] == 0x01 {
			// Ethernetが14byte, IPヘッダが20byteなので34byte目からがICMPパケット
			return parseICMP(recvBuf[34:])
		}
	}
}

func parseICMP(packet []byte) ICMP {
	return ICMP{
		Type:           []byte{packet[0]},
		Code:           []byte{packet[1]},
		CheckSum:       []byte{packet[2], packet[3]},
		Identification: []byte{packet[4], packet[5]},
		SequenceNumber: []byte{packet[6], packet[7]},
		Data:           packet[8:],
	}
}
