package main

import (
	"bytes"
	"fmt"
	"log"
	"syscall"
	"time"
)

func NewTLSRecordHeader(ctype string) TLSRecordHeader {
	var ctypeByte byte
	switch ctype {
	case "Handshake":
		ctypeByte = byte(TypeHandShake)
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
	handshake := ClientHello{
		HandshakeType:      []byte{TypeClientHello},
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

func unpackTLSHandshake(packet []byte) interface{} {
	//fmt.Printf("TLS Handshake byte : %d, %x\n", len(packet), packet)
	var i interface{}

	switch packet[0] {
	case TypeServerHello:
		i = ServerHello{
			HandshakeType:     packet[0:1],
			Length:            packet[1:4],
			Version:           packet[4:6],
			Random:            packet[6:38],
			SessionID:         packet[38:39],
			CipherSuites:      packet[40:42],
			CompressionMethod: packet[42:],
		}
	case TypeCertificate:
		i = CertifiateProto{
			HandshakeType:      packet[0:1],
			Length:             packet[1:4],
			CertificatesLength: packet[4:7],
			Certificates:       nil,
		}
	case TypeServerKeyExchange:
		i = ServerKeyExchange{
			HandshakeType:               packet[0:1],
			Length:                      packet[1:4],
			ECDiffieHellmanServerParams: packet[4:],
		}
	case TypeServerHelloDone:
		i = ServerHelloDone{
			HandshakeType: packet[0:1],
			Length:        packet[1:],
		}
	}
	return i
}

func unpackTLSPacket(packet []byte) {
	// TCPのデータをContentType、TLSバージョンのbyte配列でSplitする
	splitByte := bytes.Split(packet, []byte{0x16, 0x03, 0x03})
	for _, v := range splitByte {
		if len(v) != 0 {
			rHeader := TLSRecordHeader{
				ContentType:     []byte{0x16},
				ProtocolVersion: []byte{0x03, 0x04},
				Length:          v[0:2],
			}
			tls := unpackTLSHandshake(v[2:])
			fmt.Printf("handshak tls record header : %+v\n", rHeader)
			fmt.Printf("handshak tls record header : %+v\n", tls)
		}
	}

	//fmt.Printf("total tls length : %d\n", lenght)
	//fmt.Printf("first tls length : %d\n", sumByteArr(record.Length)+5)
	//first := packet[0 : sumByteArr(record.Length)+5]
	//_ = first
	//packet = packet[sumByteArr(record.Length)+5:]
	//fmt.Printf("total tls length : %d\n", len(packet))
}

func parseTLS(packet []byte, tlslegth uint) (TLSRecordHeader, ClientHello) {
	recordByte := packet[0:6]
	handshakeByte := packet[6:]

	record := TLSRecordHeader{
		ContentType:     recordByte[0:1],
		ProtocolVersion: recordByte[1:3],
		Length:          recordByte[3:5],
	}
	handshake := ClientHello{
		HandshakeType:     handshakeByte[0:1],
		Length:            handshakeByte[1:4],
		Version:           handshakeByte[4:6],
		Random:            handshakeByte[6:38],
		SessionID:         handshakeByte[38:40],
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
	syscall.Bind(sendfd, &syscall.SockaddrInet4{
		Port: 422779,
		Addr: [4]byte{byte(0xc0), byte(0xa8), byte(0x00), byte(0x14)},
	})
	// Client Helloを送る
	err := SendIPv4Socket(sendfd, clienthelloPacket, addr)
	if err != nil {
		return TCPHeader{}, fmt.Errorf("Send SYN packet err : %v", err)
	}
	fmt.Printf("Send TLS Client Hellow to :%s\n", tcpip.DestIP)

	var tcp TCPHeader
	for {
		recvBuf := make([]byte, 65535)
		_, _, err := syscall.Recvfrom(sendfd, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// IPヘッダをUnpackする
		ip := parseIP(recvBuf[0:20])
		if bytes.Equal(ip.Protocol, []byte{0x06}) && bytes.Equal(ip.SourceIPAddr, destIp) {
			// IPヘッダを省いて20byte目からのTCPパケットをパースする
			tcp = parseTCP(recvBuf[20:])
			//if tcp.ControlFlags[0] == ACK {
			//	fmt.Printf("Recv ACK from %s\n", tcpip.DestIP)
			//	record, handshake := parseTLS(tcpip.Data, sumByteArr(ip.TotalPacketLength)-40)
			//	if record.ContentType[0] == HandShake && handshake.HandshakeType[0] == ServerHello {
			//		fmt.Printf("Recv ServerHello from %s\n", tcpip.DestIP)
			//		break
			//	}
			//} else
			if tcp.ControlFlags[0] == PSHACK {
				fmt.Printf("Recv PSHACK from %s\n", tcpip.DestIP)
				fmt.Printf("Recv TCP Length from is %d\n", sumByteArr(ip.TotalPacketLength)-40)

				parseTLS(tcpip.Data, sumByteArr(ip.TotalPacketLength)-40)

				fmt.Printf("%s\n\n", string(tcp.TCPData))
				time.Sleep(10 * time.Millisecond)

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
