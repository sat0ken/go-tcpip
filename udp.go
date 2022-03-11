package main

import (
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

type DummyHeader struct {
	SourceIPAddr []byte
	DstIPAddr    []byte
	Data         []byte
	Protocol     []byte
	PacketLenth  []byte
}

func (*UDPHeader) Create(sourceport, destport []byte) UDPHeader {
	return UDPHeader{
		SourcePort:  sourceport,
		DestPort:    destport,
		PacketLenth: []byte{0x00, 0x00},
		Checksum:    []byte{0x00, 0x00},
	}
}

func (*DummyHeader) Create(header IPHeader) DummyHeader {
	return DummyHeader{
		SourceIPAddr: header.SourceIPAddr,
		DstIPAddr:    header.DstIPAddr,
		Data:         []byte{0x00},
		Protocol:     header.Protocol,
		PacketLenth:  []byte{0x00, 0x00},
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

	// http://www.furuta.com/yasunori/linux/raw_socket.html
	//err = syscall.SetsockoptInt(sendfd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	//if err != nil {
	//	log.Fatalf("set socket option err : %v\n", err)
	//}
	//err = syscall.SetsockoptString(sendfd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "lo")
	//if err != nil {
	//	log.Fatalf("set socket option string err : %v\n", err)
	//}

	//err = syscall.Bind(sendfd, &syscall.SockaddrInet4{
	//	Addr: [4]byte{0x00, 0x00, 0x00, 0x00},
	//	Port: 42279,
	//})
	//if err != nil {
	//	log.Fatalf("sendfd bind err : %v\n", err)
	//}

	err = syscall.Sendto(sendfd, packet, 0, &addr)
	if err != nil {
		log.Fatalf("Send to err : %v\n", err)
	}
	syscall.Close(sendfd)
}

func udpSend() {
	localmac := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	localif, err := getLocalIpAddr("lo")
	if err != nil {
		log.Fatalf("getLocalIpAddr err : %v", err)
	}
	//fmt.Printf("%+v\n", localif)
	var ip IPHeader
	ipheader := ip.Create(localif.LocalIpAddr, localif.LocalIpAddr, "UDP")

	var udp UDPHeader
	udppacket := udp.Create([]byte{0xa6, 0xe9}, []byte{0x30, 0x39})
	udpdata := []byte(`hogehoge`)

	ipheader.TotalPacketLength = uintTo2byte(uint16(20) + toByteLen(udppacket) + uint16(len(udpdata)))
	udppacket.PacketLenth = uintTo2byte(toByteLen(udppacket) + uint16(len(udpdata)))

	var dummy DummyHeader
	dummyHeader := dummy.Create(ipheader)
	dummyHeader.PacketLenth = udp.PacketLenth

	sum := sumByteArr(toByteArr(dummy))
	sum += sumByteArr(toByteArr(udppacket))
	sum += sumByteArr(udpdata)

	udppacket.Checksum = calcChecksum(sum)

	var eth EthernetFrame
	var packet []byte
	packet = append(packet, toByteArr(eth.Create(localmac, localmac, "IPv4"))...)
	packet = append(packet, toByteArr(ipheader)...)
	packet = append(packet, toByteArr(udppacket)...)
	packet = append(packet, udpdata...)

	udp.Send(packet)
}
