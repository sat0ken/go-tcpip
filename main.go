package main

import (
	"fmt"
	"log"
	"syscall"
)

func _main() {
	recvfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("create icmp recvfd err : %v\n", err)
	}
	err = syscall.Bind(recvfd, &syscall.SockaddrInet4{
		Addr: [4]byte{0x7f, 0x00, 0x00, 0x01},
	})

	if err != nil {
		log.Fatalf("bind err : %v\n", err)
	}
	for {
		recvBuf := make([]byte, 128)
		read, sockaddr, err := syscall.Recvfrom(recvfd, recvBuf, 0)
		_ = read
		_ = sockaddr
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// IPヘッダのProtocolがICMPであることをチェック
		if recvBuf[9] == 0x06 {
			parseTCP(recvBuf[20:])
			//fmt.Printf("%x\n", recvBuf[20:])
			// IPヘッダが20byteなので21byte目からがTCPパケット
			//if recvBuf[21] == 0x1f && recvBuf[22] == 0x90 {
			//	//parseTCP(recvBuf[21:])
			//	fmt.Printf("%x\n", recvBuf[21:])
			//}
		}
	}
}

func main() {
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
	// 8080
	//tcpheader = tcpheader.CreateSyn([]byte{0xa6, 0xe9}, []byte{0x1f, 0x90})
	tcpheader = tcpheader.CreateSyn([]byte{0xa6, 0xe9}, []byte{0x30, 0x39})

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

	//tcpheader.Checksum = calcChecksum(sum)
	tcpheader.Checksum = []byte{0xcc, 0xe4}

	var sendTcpSyn []byte
	//sendTcpSyn = append(sendTcpSyn, toByteArr(ethernet)...)
	sendTcpSyn = append(sendTcpSyn, toByteArr(ipheader)...)
	sendTcpSyn = append(sendTcpSyn, toByteArr(tcpheader)...)
	sendTcpSyn = append(sendTcpSyn, toByteArr(tcpOption)...)

	printByteArr(sendTcpSyn)

	addr := syscall.SockaddrInet4{
		Addr: [4]byte{0x7f, 0x00, 0x00, 0x01},
		Port: 12345,
	}
	//addr := syscall.SockaddrLinklayer{
	//	Protocol: syscall.ETH_P_IP,
	//	Ifindex:  1,
	//}

	//sendfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	sendfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		log.Fatalf("create tcp sendfd err : %v\n", err)
	}
	syscall.SetsockoptInt(sendfd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	//recvfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	//if err != nil {
	//	log.Fatalf("create tcp recvfd err : %v\n", err)
	//}
	//err = syscall.Bind(sendfd, &syscall.SockaddrInet4{
	//	Addr: [4]byte{0x7f, 0x00, 0x00, 0x01},
	//	Port: 42279,
	//})
	//if err != nil {
	//	log.Fatalf("bind err : %v\n", err)
	//}
	//err = syscall.Sendto(sendfd, sendTcpSyn, 0, &addr)
	//if err != nil {
	//	log.Fatalf("Send to err : %v\n", err)
	//}
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
		// IPヘッダのProtocolがTCPであることをチェック
		fmt.Printf("%x\n", recvBuf[:])
		//if recvBuf[9] == 0x06 {
		//	// IPヘッダが20byteなので21byte目からがTCPパケット
		//	parseTCP(recvBuf[20:])
		//	//fmt.Printf("%x\n", recvBuf[21:])
		//}
	}

	//syscall.Close(sendfd)
}
