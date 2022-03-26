package main

import (
	"fmt"
	"log"
	"syscall"
)

type DNS struct {
	TransactionID []byte
	Flags         []byte
	Questions     []byte
	Answers       []byte
	Authority     []byte
	Additional    []byte
	QueryName     []byte
	QueryType     []byte
	QueryClass    []byte
}

func NewDNSQuery(host string) DNS {
	bytehost := []byte{0x03, 0x77, 0x77, 0x77, 0x04, 0x6a, 0x70, 0x72,
		0x73, 0x02, 0x63, 0x6f, 0x02, 0x6a, 0x70, 0x00,
	}
	//if len(bytehost)%2 != 0 {
	//	bytehost = paddingZero(bytehost)
	//}

	return DNS{
		// 適当な値をセット
		TransactionID: []byte{0x00, 0x00},
		// https://atmarkit.itmedia.co.jp/ait/articles/1601/29/news014.html
		// Flags 1byte: QR = 0, OPCode = 0000, AA = 0, TC = 0, RD = 1 → 0x01
		// Flags 2byte: RA = 0, Z = 0, AD = 1, CD = 0, RCode = 0000   → 100000 = 32 = 0x20
		Flags:      []byte{0x01, 0x00},
		Questions:  []byte{0x00, 0x01},
		Answers:    []byte{0x00, 0x00},
		Authority:  []byte{0x00, 0x00},
		Additional: []byte{0x00, 0x00},
		QueryName:  bytehost,
		QueryType:  []byte{0x00, 0x01},
		QueryClass: []byte{0x00, 0x01},
	}

}

func (*DNS) SendQuery(packet []byte) {
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

func sendDNS() {
	//　ルータのMacアドレス
	routermac := []byte{0x1c, 0x3b, 0xf3, 0x95, 0x6a, 0x2c}

	localif, err := getLocalIpAddr("wlp4s0")
	if err != nil {
		log.Fatalf("getLocalIpAddr err : %v", err)
	}

	ipheader := NewIPHeader(localif.LocalIpAddr, iptobyte("192.168.0.254"), "UDP")

	//var udp UDPHeader
	udpheader := NewUDPHeader(uintTo2byte(42279), uintTo2byte(53))
	dnspacket := NewDNSQuery(".github.com")
	udpdata := toByteArr(dnspacket)

	fmt.Printf("dns packet : %s\n", printByteArr(udpdata))

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
	packet = append(packet, toByteArr(NewEthernet(routermac, localif.LocalMacAddr, "IPv4"))...)
	packet = append(packet, toByteArr(ipheader)...)
	packet = append(packet, toByteArr(udpheader)...)
	packet = append(packet, udpdata...)

	go udpheader.recv(localif.LocalIpAddr)

	udpheader.Send(packet)
}
