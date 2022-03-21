package main

import (
	"fmt"
	"log"
	"syscall"
)

// https://www.infraexpert.com/study/tcpip12.html
type UDPHeader struct {
	SourcePort  []byte
	DestPort    []byte
	PacketLenth []byte
	Checksum    []byte
}

type UDPDummyHeader struct {
	SourceIPAddr []byte
	DstIPAddr    []byte
	Protocol     []byte
	Length       []byte
}

func NewUDPHeader(sourceport, destport []byte) UDPHeader {
	return UDPHeader{
		SourcePort:  sourceport,
		DestPort:    destport,
		PacketLenth: []byte{0x00, 0x00},
		Checksum:    []byte{0x00, 0x00},
	}
}

func NewUDPDummyHeader(header IPHeader) UDPDummyHeader {
	return UDPDummyHeader{
		SourceIPAddr: header.SourceIPAddr,
		DstIPAddr:    header.DstIPAddr,
		Protocol:     []byte{0x00, 0x11},
		Length:       []byte{0x00, 0x00},
	}
}

func (*UDPHeader) Send(packet []byte) {
	addr := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_IP,
		Ifindex:  1,
	}

	sendfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("create udp sendfd err : %v\n", err)
	}

	err = syscall.Sendto(sendfd, packet, 0, &addr)
	if err != nil {
		log.Fatalf("Send to err : %v\n", err)
	}
	fmt.Println("UDP packet send")
	syscall.Close(sendfd)
}

func udpSend() {
	localmac := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	localif, err := getLocalIpAddr("lo")
	if err != nil {
		log.Fatalf("getLocalIpAddr err : %v", err)
	}

	ipheader := NewIPHeader(localif.LocalIpAddr, localif.LocalIpAddr, "UDP")

	//var udp UDPHeader
	udpheader := NewUDPHeader(uintTo2byte(42279), uintTo2byte(12345))
	udpdata := []byte(`hogehoge`)

	ipheader.TotalPacketLength = uintTo2byte(uint16(20) + toByteLen(udpheader) + uint16(len(udpdata)))
	udpheader.PacketLenth = uintTo2byte(toByteLen(udpheader) + uint16(len(udpdata)))

	// IPヘッダのチェックサムを計算する
	ipsum := sumByteArr(toByteArr(ipheader))
	ipheader.HeaderCheckSum = checksum(ipsum)

	dummyHeader := NewUDPDummyHeader(ipheader)
	dummyHeader.Length = udpheader.PacketLenth

	sum := sumByteArr(toByteArr(dummyHeader))
	sum += sumByteArr(toByteArr(udpheader))
	sum += sumByteArr(udpdata)

	// UDPヘッダ+データのチェックサムを計算する
	udpheader.Checksum = checksum(sum)

	var packet []byte
	packet = append(packet, toByteArr(NewEthernet(localmac, localmac, "IPv4"))...)
	packet = append(packet, toByteArr(ipheader)...)
	packet = append(packet, toByteArr(udpheader)...)
	packet = append(packet, udpdata...)

	udpheader.Send(packet)
}
