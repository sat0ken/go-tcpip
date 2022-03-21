package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"syscall"
	"time"
)

func calcSequenceNumber(packet []byte, add uint32) []byte {
	var sum uint32
	sum = binary.BigEndian.Uint32(packet) + add

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, sum)

	return b
}

func startConnection(sendfd int, tcpip TCPIP) TCPIP {

	synPacket := NewTCPIP(tcpip)
	destIp := iptobyte(tcpip.DestIP)
	destPort := uintTo2byte(tcpip.DestPort)

	addr := syscall.SockaddrInet4{
		Addr: [4]byte{destIp[0], destIp[1], destIp[2], destIp[3]},
		Port: int(tcpip.DestPort),
	}

	err := SocketSend(sendfd, synPacket, addr)
	if err != nil {
		log.Fatalf("Send SYN packet err : %v\n", err)
	}

	//chanpacket := make(chan TCPHeader)
	synack := SocketRecvfrom(sendfd, destIp, destPort)

	var ack TCPIP
	// 0x12 = SYNACK
	if bytes.Equal(synack.ControlFlags, []byte{0x12}) {
		// SYNACKに対してACKを送り返す
		ack = TCPIP{
			DestIP:    tcpip.DestIP,
			DestPort:  tcpip.DestPort,
			TcpFlag:   "ACK",
			SeqNumber: synack.AcknowlegeNumber,
			AckNumber: calcSequenceNumber(synack.SequenceNumber, 1),
			//AckNumber: synack.SequenceNumber,
			//AckNumber: calcSequenceNumber(synack.SequenceNumber, 1),
		}
		ackPacket := NewTCPIP(ack)
		err = SocketSend(sendfd, ackPacket, addr)
	} else if bytes.Equal(synack.ControlFlags, []byte{0x11}) { // 0x11 = FINACK
		ack = TCPIP{
			DestIP:    tcpip.DestIP,
			DestPort:  tcpip.DestPort,
			TcpFlag:   "ACK",
			SeqNumber: synack.AcknowlegeNumber,
			AckNumber: calcSequenceNumber(synack.SequenceNumber, 1),
		}
		ackPacket := NewTCPIP(ack)
		err = SocketSend(sendfd, ackPacket, addr)
	} else if bytes.Equal(synack.ControlFlags, []byte{0x10}) {
		ack = TCPIP{
			DestIP:    tcpip.DestIP,
			DestPort:  tcpip.DestPort,
			TcpFlag:   "ACK",
			SeqNumber: synack.AcknowlegeNumber,
			AckNumber: calcSequenceNumber(synack.SequenceNumber, 1),
		}
		ackPacket := NewTCPIP(ack)
		err = SocketSend(sendfd, ackPacket, addr)
	}

	return ack
}

func sendToNginx(sendfd int, tcpip TCPIP) {
	pshPacket := NewTCPIP(tcpip)
	destIp := iptobyte(tcpip.DestIP)
	destPort := uintTo2byte(tcpip.DestPort)
	addr := syscall.SockaddrInet4{
		Addr: [4]byte{destIp[0], destIp[1], destIp[2], destIp[3]},
		Port: int(tcpip.DestPort),
	}

	recv := NewSocket(syscall.AF_INET, syscall.IPPROTO_TCP)
	syscall.Bind(recv, &syscall.SockaddrInet4{
		Addr: [4]byte{127, 0, 0, 1},
		Port: 42279,
	})

	// httpをおくる
	err := SocketSend(sendfd, pshPacket, addr)
	if err != nil {
		log.Fatalf("Send PSH packet err : %v\n", err)
	}
	var http_pshack TCPHeader
	var tolalLength uint32
	for {
		recvBuf := make([]byte, 1500)
		read, sockaddr, err := syscall.Recvfrom(recv, recvBuf, 0)
		_ = read
		_ = sockaddr
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// IPヘッダのProtocolがTCPであることをチェック
		if recvBuf[9] == 0x06 && bytes.Equal(recvBuf[16:20], destIp) && bytes.Equal(recvBuf[20:22], destPort) {
			tolalLength = uint32(sumByteArr(recvBuf[2:4]))

			// IPヘッダを省いて20byte目からのTCPパケットをパースする
			http_pshack = parseTCP(recvBuf[20:])
			// PSH ACKであれば
			if bytes.Equal(http_pshack.ControlFlags, []byte{0x18}) {
				fmt.Println("----- print HTTP Renponse -----")
				fmt.Printf("%s\n\n", string(http_pshack.TCPData))
				time.Sleep(100 * time.Millisecond)
				tcpLength := tolalLength - 20
				tcpLength = tcpLength - uint32(http_pshack.HeaderLength[0]>>4<<2)

				ack := TCPIP{
					DestIP:    tcpip.DestIP,
					DestPort:  tcpip.DestPort,
					TcpFlag:   "ACK",
					SeqNumber: http_pshack.AcknowlegeNumber,
					AckNumber: calcSequenceNumber(http_pshack.SequenceNumber, tcpLength),
				}
				ackPacket := NewTCPIP(ack)
				// HTTPを受信したことに対してACKを送る
				SocketSend(sendfd, ackPacket, addr)
				//time.Sleep(100 * time.Millisecond)
				fmt.Println("Send ACK to server")

			} else if bytes.Equal(http_pshack.ControlFlags, []byte{0x11}) { //FIN ACKであれば
				fmt.Println("recv FINACK from server")
				finack := TCPIP{
					DestIP:    tcpip.DestIP,
					DestPort:  tcpip.DestPort,
					TcpFlag:   "FINACK",
					SeqNumber: http_pshack.AcknowlegeNumber,
					AckNumber: calcSequenceNumber(http_pshack.SequenceNumber, 1),
				}
				send_finackPacket := NewTCPIP(finack)
				SocketSend(sendfd, send_finackPacket, addr)
				fmt.Println("Send FINACK to server")
				time.Sleep(100 * time.Millisecond)
				break
			}
			//else if bytes.Equal(http_pshack.ControlFlags, []byte{0x10}) {
			//	fmt.Println("recv ACK from server")
			//	break
			//}
		}
	}

	syscall.Close(sendfd)
	syscall.Close(recv)

}
