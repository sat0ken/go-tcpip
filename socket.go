package main

import (
	"bytes"
	"fmt"
	"log"
	"syscall"
)

func NewSocket(domain, protocol int) int {
	sendfd, err := syscall.Socket(domain, syscall.SOCK_RAW, protocol)
	if err != nil {
		log.Fatalf("create tcp sendfd err : %v\n", err)
	}
	if protocol == syscall.IPPROTO_TCP {
		syscall.SetsockoptInt(sendfd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
		syscall.SetsockoptInt(sendfd, syscall.IPPROTO_TCP, syscall.SO_SNDTIMEO, 1)
	}
	return sendfd
}

func SocketSend(fd int, packet []byte, addr syscall.SockaddrInet4) error {
	err := syscall.Sendto(fd, packet, 0, &addr)
	if err != nil {
		return err
	}
	return nil
}

func SocketRecvfrom(fd int, destIp, destPort []byte) TCPHeader {
	var synack TCPHeader

	for {
		recvBuf := make([]byte, 128)
		_, _, err := syscall.Recvfrom(fd, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// IPヘッダのProtocolがTCPであるか、 IPヘッダのDestinationのIPが同じであるか、TCPヘッダのSourceポートが送信先ポートと同じであるか
		if recvBuf[9] == 0x06 && bytes.Equal(recvBuf[16:20], destIp) && bytes.Equal(recvBuf[20:22], destPort) {
			// IPヘッダを省いて20byte目からのTCPパケットをパースする
			fmt.Printf("%x\n", recvBuf[20:])
			synack = parseTCP(recvBuf[20:])
			break
		}
	}
	return synack
}
