package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"syscall"
	"time"
)

// https://www.infraexpert.com/study/tcpip8.html
type TCPHeader struct {
	SourcePort       []byte
	DestPort         []byte
	SequenceNumber   []byte
	AcknowlegeNumber []byte
	HeaderLength     []byte
	ControlFlags     []byte
	WindowSize       []byte
	Checksum         []byte
	UrgentPointer    []byte
	TCPOptionByte    []byte
}

type TCPOpstions struct {
	MaxsSegmentSize []byte
	SackPermitted   []byte
	Timestamps      []byte
	NoOperation     []byte
	WindowScale     []byte
}

func (*TCPHeader) CreateSyn(sourceport, destport []byte) TCPHeader {
	return TCPHeader{
		SourcePort:       sourceport,
		DestPort:         destport,
		SequenceNumber:   []byte{0x2b, 0xed, 0x50, 0x49},
		AcknowlegeNumber: []byte{0x00, 0x00, 0x00, 0x00},
		HeaderLength:     []byte{0x00},
		ControlFlags:     []byte{0x02},
		//WindowSize:       []byte{0xff, 0xd7},
		WindowSize:    []byte{0x16, 0xd0},
		Checksum:      []byte{0x00, 0x00},
		UrgentPointer: []byte{0x00, 0x00},
	}
}

func createTCPTimestamp() []byte {
	t := time.Now()
	t.AddDate(1, 1, 1)

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(t.Unix()))

	return b
}

// https://milestone-of-se.nesuke.com/nw-basic/tcp-udp/tcp-option/
func (*TCPOpstions) Create() TCPOpstions {
	tcpoption := TCPOpstions{
		// オプション番号2, Length, 値(2byte)
		//MaxsSegmentSize: []byte{0x02, 0x04, 0xff, 0xd7},
		MaxsSegmentSize: []byte{0x02, 0x04, 0x00, 0x30},
		// オプション番号4, Length + EndOfList
		SackPermitted: []byte{0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		// オプション番号1
		//NoOperation: []byte{0x01},
		// オプション番号3, Length, 値(1byte)
		//WindowScale: []byte{0x03, 0x03, 0x07},
		// オプション番号8, Length, Timestamp value(4byte), echo reply(4byte)
		//Timestamps: []byte{0x08, 0x0a},
	}

	// Timestamp value(4byte)を追加
	//tcpoption.Timestamps = append(tcpoption.Timestamps, createTCPTimestamp()...)
	//tcpoption.Timestamps = append(tcpoption.Timestamps, []byte{0x80, 0x6a, 0x9b, 0xca}...)
	// echo reply(4byte)を追加
	//tcpoption.Timestamps = append(tcpoption.Timestamps, []byte{0x00, 0x00, 0x00, 0x00}...)

	return tcpoption
}

func parseTCP(packet []byte) {
	if packet[0] == 0x1f && packet[1] == 0x90 {
		switch packet[13] {
		case 0x12:
			fmt.Printf("SYN ACK from %x\n", packet[0:1])
		case 0x10:
			fmt.Printf("ACK from %x\n", packet[0:1])
		case 0x18:
			fmt.Printf("PSH, ACK from %x\n", packet[0:1])
		case 0x11:
			fmt.Printf("FIN, ACK from %x\n", packet[0:1])
		}
	}
}

func connect() {
	localmac := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	localif, err := getLocalIpAddr("lo")
	if err != nil {
		log.Fatalf("getLocalIpAddr err : %v", err)
	}

	var ethernet EthernetFrame
	ethernet = ethernet.Create(localmac, localmac, "IPv4")

	var ipheader IPHeader
	ipheader = ipheader.Create(localif.LocalIpAddr, localif.LocalIpAddr, "TCP")

	var tcpheader TCPHeader
	tcpheader = tcpheader.CreateSyn([]byte{0xa6, 0xe9}, []byte{0x1f, 0x90})

	var tcpOption TCPOpstions
	tcpOption = tcpOption.Create()

	// IP=20byte + tcpヘッダの長さ + tcpオプションの長さ
	ipheader.TotalPacketLength = uintTo2byte(20 + toByteLen(tcpheader) + toByteLen(tcpOption))

	num := toByteLen(tcpheader) + toByteLen(tcpOption)
	tcpheader.HeaderLength = []byte{byte(num << 2)}

	var dummy DummyHeader
	dummyHeader := dummy.Create(ipheader)
	dummyHeader.PacketLenth = tcpheader.HeaderLength

	sum := sumByteArr(toByteArr(dummy))
	sum += sumByteArr(toByteArr(tcpheader))
	sum += sumByteArr(toByteArr(tcpOption))

	tcpheader.Checksum = calcChecksum(sum)

	var sendTcpSyn []byte
	//sendTcpSyn = append(sendTcpSyn, toByteArr(ethernet)...)
	sendTcpSyn = append(sendTcpSyn, toByteArr(ipheader)...)
	sendTcpSyn = append(sendTcpSyn, toByteArr(tcpheader)...)
	sendTcpSyn = append(sendTcpSyn, toByteArr(tcpOption)...)

	addr := syscall.SockaddrInet4{
		Addr: [4]byte{0x7f, 0x00, 0x00, 0x01},
		Port: 8080,
	}
	//addr := syscall.SockaddrLinklayer{
	//	Protocol: syscall.ETH_P_IP,
	//	Ifindex:  1,
	//}

	//sendfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	sendfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("create tcp sendfd err : %v\n", err)
	}
	syscall.SetsockoptInt(sendfd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	syscall.SetsockoptInt(sendfd, syscall.SOL_SOCKET, syscall.TCP_NODELAY, 1)
	syscall.SetsockoptInt(sendfd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)

	err = syscall.Connect(sendfd, &addr)
	if err != nil {
		log.Fatalf("Connect err : %v\n", err)
	}

	err = syscall.Sendto(sendfd, sendTcpSyn, 0, &addr)
	if err != nil {
		log.Fatalf("Send to err : %v\n", err)
	}

	for {
		recvBuf := make([]byte, 128)
		read, sockaddr, err := syscall.Recvfrom(sendfd, recvBuf, 0)
		_ = read
		_ = sockaddr
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// IPヘッダのProtocolがICMPであることをチェック
		if recvBuf[9] == 0x06 {
			// IPヘッダが20byteなので21byte目からがICMPパケット
			parseTCP(recvBuf[20:])
			//fmt.Printf("%x\n", recvBuf[21:])
		}
	}

	//syscall.Close(sendfd)
}
