package main

import (
	"bytes"
	"fmt"
	"log"
	"syscall"
	"time"
)

const (
	ClientHello       = 0x01
	ServerHello       = 0x02
	ClientKeyExchange = 0x10 //=16
	HandShake         = 0x16
)

var TLS1_2 = []byte{0x03, 0x03}

// https://www.ipa.go.jp/security/rfc/RFC5246-AAJA.html
type TLSRecordHeader struct {
	ContentType     []byte
	ProtocolVersion []byte
	Length          []byte
}

type TLSHandshake struct {
	HandshakeType      []byte
	Length             []byte
	Version            []byte
	Random             []byte
	SessionID          []byte
	CipherSuitesLength []byte
	CipherSuites       []byte
	CompressionLength  []byte
	CompressionMethod  []byte
	ExtensionLength    []byte
	Extension          []byte
}

func NewTLSRecordHeader(ctype string) TLSRecordHeader {
	var ctypeByte byte
	switch ctype {
	case "Handshake":
		ctypeByte = byte(HandShake)
	case "AppDada":
		ctypeByte = byte(23)
	case "Alert":
		ctypeByte = byte(21)
	case "ChangeCipherSpec":
		ctypeByte = byte(20)
	}
	return TLSRecordHeader{
		ContentType: []byte{ctypeByte},
		// TLS 1.2
		ProtocolVersion: TLS1_2,
		Length:          []byte{0x00, 0x00},
	}
}

func NewClientHello() []byte {
	record := NewTLSRecordHeader("Handshake")
	cipher := getChipersList()
	handshake := TLSHandshake{
		HandshakeType:      []byte{ClientHello},
		Length:             []byte{0x00, 0x00, 0x00},
		Version:            TLS1_2,
		Random:             random32byte(),
		SessionID:          []byte{0x00},
		CipherSuitesLength: uintTo2byte(uint16(len(cipher))),
		CipherSuites:       cipher,
		CompressionLength:  []byte{0x01},
		CompressionMethod:  []byte{0x00},
	}

	record.Length = uintTo2byte(toByteLen(handshake))
	handshake.Length = uintTo3byte(uint32(toByteLen(handshake) - 4))

	var hello []byte
	hello = append(hello, toByteArr(record)...)
	hello = append(hello, toByteArr(handshake)...)

	return hello
}

func parseTLS(packet []byte) (TLSRecordHeader, TLSHandshake) {
	recordByte := packet[0:6]
	handshakeByte := packet[6:]

	record := TLSRecordHeader{
		ContentType:     recordByte[0:1],
		ProtocolVersion: recordByte[1:3],
		Length:          recordByte[3:5],
	}
	handshake := TLSHandshake{
		HandshakeType:     handshakeByte[0:1],
		Length:            handshakeByte[1:4],
		Version:           handshakeByte[4:6],
		Random:            handshakeByte[7:39],
		SessionID:         handshakeByte[39:40],
		CipherSuites:      handshakeByte[40:42],
		CompressionMethod: handshakeByte[42:43],
	}

	return record, handshake
}

func startTLSHandshake(sendfd int, tcpip TCPIP) (TCPHeader, error) {
	clienthelloPacket := NewTCPIP(tcpip)

	destIp := iptobyte(tcpip.DestIP)
	//destPort := uintTo2byte(tcpip.DestPort)

	addr := setSockAddrInet4(destIp, int(tcpip.DestPort))
	// Client Helloを送る
	err := SendIPv4Socket(sendfd, clienthelloPacket, addr)
	if err != nil {
		return TCPHeader{}, fmt.Errorf("Send SYN packet err : %v", err)
	}
	fmt.Printf("Send TLS Client Hellow to :%s\n", tcpip.DestIP)

	var tcp TCPHeader
	for {
		recvBuf := make([]byte, 1500)
		_, _, err := syscall.Recvfrom(sendfd, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// IPヘッダをUnpackする
		ip := parseIP(recvBuf[0:20])
		if bytes.Equal(ip.Protocol, []byte{0x06}) && bytes.Equal(ip.SourceIPAddr, destIp) {
			// IPヘッダを省いて20byte目からのTCPパケットをパースする
			tcp = parseTCP(recvBuf[20:])
			if tcp.ControlFlags[0] == ACK {
				fmt.Printf("Recv ACK from %s\n", tcpip.DestIP)
				record, handshake := parseTLS(tcpip.Data)
				if record.ContentType[0] == HandShake && handshake.HandshakeType[0] == ServerHello {
					fmt.Printf("Recv ServerHello from %s\n", tcpip.DestIP)
					break
				}
			} else if tcp.ControlFlags[0] == PSHACK {
				fmt.Printf("Recv PSHACK from %s\n", tcpip.DestIP)
				//fmt.Printf("%s\n\n", string(tcp.TCPData))
				time.Sleep(10 * time.Millisecond)

				record, handshake := parseTLS(tcpip.Data)
				if record.ContentType[0] == HandShake && handshake.HandshakeType[0] == ServerHello {
					fmt.Printf("Recv ServerHello from %s\n", tcpip.DestIP)
				}

				tcpLength := uint32(sumByteArr(ip.TotalPacketLength)) - 20
				tcpLength = tcpLength - uint32(tcp.HeaderLength[0]>>4<<2)
				ack := TCPIP{
					DestIP:    tcpip.DestIP,
					DestPort:  tcpip.DestPort,
					TcpFlag:   "ACK",
					SeqNumber: tcp.AcknowlegeNumber,
					AckNumber: calcSequenceNumber(tcp.SequenceNumber, tcpLength),
				}
				ackPacket := NewTCPIP(ack)
				// HTTPを受信したことに対してACKを送る
				SendIPv4Socket(sendfd, ackPacket, addr)
				//time.Sleep(100 * time.Millisecond)
				fmt.Println("Send ACK to server")
				break
			} else if tcp.ControlFlags[0] == FINACK { //FIN ACKであれば
				fmt.Println("recv FINACK from server")
				finack := TCPIP{
					DestIP:    tcpip.DestIP,
					DestPort:  tcpip.DestPort,
					TcpFlag:   "FINACK",
					SeqNumber: tcp.AcknowlegeNumber,
					AckNumber: calcSequenceNumber(tcp.SequenceNumber, 1),
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
	return tcp, nil
}
