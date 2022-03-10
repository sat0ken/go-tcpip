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

func (*ICMP) Create() ICMP {
	// https://www.infraexpert.com/study/tcpip4.html
	icmp := ICMP{
		// ping request
		Type:           []byte{0x08},
		Code:           []byte{0x00},
		CheckSum:       []byte{0x00, 0x00},
		Identification: []byte{0x00, 0x10},
		SequenceNumber: []byte{0x00, 0x01},
		Data: []byte{
			0xb2, 0x48, 0x12, 0x62, 0x00, 0x00, 0x00, 0x00, // for timestamp
			0xeb, 0x46, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, // data
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
			0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		},
	}
	// checksumを計算したらセットしてreturnする
	icmpsum := sumByteArr(toByteArr(icmp))
	icmp.CheckSum = calcChecksum(icmpsum)

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

	recvfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		log.Fatalf("create icmp recvfd err : %v\n", err)
	}

	err = syscall.Bind(recvfd, &syscall.SockaddrInet4{
		Addr: [4]byte{0xc0, 0xa8, 0x00, 0x06},
	})
	if err != nil {
		log.Fatalf("bind err : %v\n", err)
	}

	err = syscall.Sendto(sendfd, packet, 0, &addr)
	if err != nil {
		log.Fatalf("Send to err : %v\n", err)
	}

	for {
		recvBuf := make([]byte, 1500)
		read, sockaddr, err := syscall.Recvfrom(recvfd, recvBuf, 0)
		_ = read
		_ = sockaddr
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// IPヘッダのProtocolがICMPであることをチェック
		if recvBuf[9] == 0x01 {
			// IPヘッダが20byteなので21byte目からがICMPパケット
			return parseICMP(recvBuf[21:])
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

func sendArpICMP() {

	localif, err := getLocalIpAddr("wlp4s0")
	if err != nil {
		log.Fatalf("getLocalIpAddr err : %v", err)
	}

	var ethernet EthernetFrame
	var arp Arp
	arpPacket := arp.Request(localif)

	var sendArp []byte
	sendArp = append(sendArp, toByteArr(ethernet.Create([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, localif.LocalMacAddr, "ARP"))...)
	sendArp = append(sendArp, toByteArr(arpPacket)...)

	arpreply := arp.Send(localif.Index, sendArp)
	fmt.Printf("ARP Reply : %+v\n", arpreply)

	var icmp ICMP
	var ip IPHeader
	var sendIcmp []byte

	icmpPacket := icmp.Create()
	header := ip.Create(localif.LocalIpAddr, []byte{0xc0, 0xa8, 0x00, 0x0f}, "IP")
	header.TotalPacketLength = uintTo2byte(toByteLen(header) + toByteLen(icmpPacket))

	sendIcmp = append(sendIcmp, toByteArr(ethernet.Create(arpreply.SenderMacAddr, localif.LocalMacAddr, "IPv4"))...)
	sendIcmp = append(sendIcmp, toByteArr(header)...)
	sendIcmp = append(sendIcmp, toByteArr(icmpPacket)...)

	icmpreply := icmp.Send(localif.Index, sendIcmp)
	fmt.Printf("ICMP Reply : %+v\n", icmpreply)
}
