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

func setSockAddrInet4(destIp []byte, destPort int) syscall.SockaddrInet4 {
	return syscall.SockaddrInet4{
		Addr: [4]byte{destIp[0], destIp[1], destIp[2], destIp[3]},
		Port: destPort,
	}
}

func startConnectionFromEth(sendfd int, tcpip TCPIP) (TCPIP, error) {
	localif, _ := getLocalIpAddr("lo")

	synPacket := NewPacket(tcpip)
	destIp := localif.LocalIpAddr
	destPort := uintTo2byte(tcpip.DestPort)

	addr := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_IP,
		Ifindex:  localif.Index,
	}
	err := SendRaw(sendfd, synPacket, addr)
	if err != nil {
		return TCPIP{}, fmt.Errorf("Send SYN packet err : %v\n", err)
	}
	fmt.Println("Send SYN packet")

	synack := SocketRecvfromEth(sendfd, destIp, destPort)

	var ack TCPIP
	// 0x12 = SYNACK, 0x11 = FINACK, 0x10 = ACK
	if synack.ControlFlags[0] == SYNACK || synack.ControlFlags[0] == FINACK || synack.ControlFlags[0] == ACK {
		// SYNACKに対してACKを送り返す
		ack = TCPIP{
			DestIP:    tcpip.DestIP,
			DestPort:  tcpip.DestPort,
			TcpFlag:   "ACK",
			SeqNumber: synack.AcknowlegeNumber,
			AckNumber: calcSequenceNumber(synack.SequenceNumber, 1),
		}
		ackPacket := NewPacket(ack)
		err = SendRaw(sendfd, ackPacket, addr)
		if err != nil {
			return TCPIP{}, fmt.Errorf("Send ACK packet err : %v\n", err)
		}
	}

	return ack, nil

}

func startTCPConnection(sendfd int, tcpip TCPIP) (TCPIP, error) {

	synPacket := NewTCPIP(tcpip)
	destIp := iptobyte(tcpip.DestIP)
	destPort := uintTo2byte(tcpip.DestPort)

	addr := setSockAddrInet4(destIp, int(tcpip.DestPort))

	// SYNを送る
	err := SendIPv4Socket(sendfd, synPacket, addr)
	if err != nil {
		return TCPIP{}, fmt.Errorf("Send SYN packet err : %v\n", err)
	}
	fmt.Println("Send SYN packet")

	// SYNACKを受け取る
	synack := RecvIPSocket(sendfd, destIp, destPort)

	var ack TCPIP
	// 0x12 = SYNACK, 0x11 = FINACK, 0x10 = ACK
	if synack.ControlFlags[0] == SYNACK || synack.ControlFlags[0] == FINACK { //|| synack.ControlFlags[0] == ACK {
		// SYNACKに対してACKを送り返す
		ack = TCPIP{
			DestIP:    tcpip.DestIP,
			DestPort:  tcpip.DestPort,
			TcpFlag:   "ACK",
			SeqNumber: synack.AcknowlegeNumber,
			AckNumber: calcSequenceNumber(synack.SequenceNumber, 1),
		}
		ackPacket := NewTCPIP(ack)
		err = SendIPv4Socket(sendfd, ackPacket, addr)
		if err != nil {
			return TCPIP{}, fmt.Errorf("Send ACK packet err : %v\n", err)
		}
	}

	return ack, nil
}

func sendNginx(sendfd int, tcpip TCPIP) {
	pshPacket := NewTCPIP(tcpip)
	destIp := iptobyte(tcpip.DestIP)
	destPort := uintTo2byte(tcpip.DestPort)

	addr := setSockAddrInet4(destIp, int(tcpip.DestPort))

	// httpリクエストを送る
	err := SendIPv4Socket(sendfd, pshPacket, addr)
	if err != nil {
		log.Fatalf("Send PSH packet err : %v\n", err)
	}
	var serverPshack TCPHeader
	var tolalLength uint32
	for {
		recvBuf := make([]byte, 1500)
		_, _, err := syscall.Recvfrom(sendfd, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// IPヘッダのProtocolがTCPであることをチェック
		if recvBuf[9] == 0x06 && bytes.Equal(recvBuf[16:20], destIp) && bytes.Equal(recvBuf[20:22], destPort) {
			tolalLength = uint32(sumByteArr(recvBuf[2:4]))

			// IPヘッダを省いて20byte目からのTCPパケットをパースする
			serverPshack = parseTCP(recvBuf[20:])
			if serverPshack.ControlFlags[0] == PSHACK {
				fmt.Println("recv PSHACK from server")
				fmt.Printf("----- print HTTP Renponse -----\n")
				fmt.Printf("%s\n\n", string(serverPshack.TCPData))
				time.Sleep(100 * time.Millisecond)
				tcpLength := tolalLength - 20
				tcpLength = tcpLength - uint32(serverPshack.HeaderLength[0]>>4<<2)

				ack := TCPIP{
					DestIP:    tcpip.DestIP,
					DestPort:  tcpip.DestPort,
					TcpFlag:   "ACK",
					SeqNumber: serverPshack.AcknowlegeNumber,
					AckNumber: calcSequenceNumber(serverPshack.SequenceNumber, tcpLength),
				}
				ackPacket := NewTCPIP(ack)
				// HTTPを受信したことに対してACKを送る
				SendIPv4Socket(sendfd, ackPacket, addr)
				//time.Sleep(100 * time.Millisecond)
				fmt.Println("Send ACK to server")

			} else if serverPshack.ControlFlags[0] == FINACK { //FIN ACKであれば
				fmt.Println("recv FINACK from server")
				finack := TCPIP{
					DestIP:    tcpip.DestIP,
					DestPort:  tcpip.DestPort,
					TcpFlag:   "FINACK",
					SeqNumber: serverPshack.AcknowlegeNumber,
					AckNumber: calcSequenceNumber(serverPshack.SequenceNumber, 1),
				}
				send_finackPacket := NewTCPIP(finack)
				SendIPv4Socket(sendfd, send_finackPacket, addr)
				fmt.Println("Send FINACK to server")
				time.Sleep(100 * time.Millisecond)
				// FINACKを送ったら終了なのでbreakスルー
				break
			}
		}
	}
	syscall.Close(sendfd)
}
