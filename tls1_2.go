package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"syscall"
	"time"
)

func (*TLSRecordHeader) NewTLSRecordHeader(ctype string) TLSRecordHeader {
	var ctypeByte byte
	switch ctype {
	case "Handshake":
		ctypeByte = byte(TypeHandShake)
	case "AppDada":
		ctypeByte = byte(23)
	case "Alert":
		ctypeByte = byte(21)
	case "ChangeCipherSpec":
		ctypeByte = byte(TypeChangeCipherSpec)
	}
	return TLSRecordHeader{
		ContentType: []byte{ctypeByte},
		// TLS 1.2
		ProtocolVersion: TLS1_2,
		Length:          []byte{0x00, 0x00},
	}
}

func (*ClientHello) NewClientHello() []byte {
	var record TLSRecordHeader
	record = record.NewTLSRecordHeader("Handshake")

	cipher := getChipersList()
	handshake := ClientHello{
		HandshakeType:      []byte{TypeClientHello},
		Length:             []byte{0x00, 0x00, 0x00},
		Version:            TLS1_2,
		Random:             randomByte(32),
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

func (*ClientKeyExchange) NewClientKeyExchange(pubkey *rsa.PublicKey) []byte {
	var record TLSRecordHeader
	record = record.NewTLSRecordHeader("Handshake")

	var premasterByte []byte

	// 46byteのランダムなpremaster secretを生成する
	// https://www.ipa.go.jp/security/rfc/RFC5246-07JA.html#07471
	premaster := randomByte(46)
	premasterByte = append(premasterByte, TLS1_2...)
	premasterByte = append(premasterByte, premaster...)

	//サーバの公開鍵で暗号化する
	secret, err := rsa.EncryptPKCS1v15(rand.Reader, pubkey, premasterByte)
	if err != nil {
		log.Fatalf("create premaster secret err : %v\n", err)
	}

	clientKey := ClientKeyExchange{
		HandshakeType:                  []byte{TypeClientKeyExchange},
		Length:                         []byte{0x00, 0x00, 0x00},
		EncryptedPreMasterSecretLength: uintTo2byte(uint16(len(secret))),
		EncryptedPreMasterSecret:       secret,
	}

	// それぞれのLengthをセット
	record.Length = uintTo2byte(toByteLen(clientKey))
	clientKey.Length = uintTo3byte(uint32(toByteLen(clientKey) - 4))

	// byte配列にする
	var clientKeyExchange []byte
	clientKeyExchange = append(clientKeyExchange, toByteArr(record)...)
	clientKeyExchange = append(clientKeyExchange, toByteArr(clientKey)...)

	return clientKeyExchange
}

func NewChangeCipherSpec() []byte {
	var record TLSRecordHeader
	record = record.NewTLSRecordHeader("ChangeCipherSpec")
	record.Length = []byte{0x00, 0x01}

	var changeCipher []byte
	changeCipher = append(changeCipher, toByteArr(record)...)
	// Change Cipher Spec Message
	changeCipher = append(changeCipher, byte(0x01))

	return changeCipher
}

func readCertificates(packet []byte) []*x509.Certificate {

	var b []byte
	var certificates []*x509.Certificate

	//　https://pkg.go.dev/crypto/x509#SystemCertPool
	// OSにインストールされている証明書を読み込む
	ospool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatalf("get SystemCertPool err : %v\n", err)
	}

	// TLS Handshak protocolのCertificatesのLengthが0になるまでx509証明書をReadする
	// 読み込んだx509証明書を配列に入れる
	for {
		if len(packet) == 0 {
			break
		} else {
			length := sum3BytetoLength(packet[0:3])
			//b := make([]byte, length)
			b = readByteNum(packet, 3, int64(length))
			cert, err := x509.ParseCertificate(b)
			if err != nil {
				log.Fatalf("ParseCertificate error : %v\n", err)
			}
			certificates = append(certificates, cert)
			//byte配列を縮める
			packet = packet[3+length:]
		}
	}

	// 証明書を検証する
	// 配列にはサーバ証明書、中間証明書の順番で格納されているので中間証明書から検証していくので
	// forloopをdecrementで回す
	for i := len(certificates) - 1; i >= 0; i-- {
		var opts x509.VerifyOptions
		if len(certificates[i].DNSNames) == 0 {
			opts = x509.VerifyOptions{
				Roots: ospool,
			}
		} else {
			opts = x509.VerifyOptions{
				DNSName: certificates[i].DNSNames[0],
				Roots:   ospool,
			}
		}

		// 検証
		_, err = certificates[i].Verify(opts)
		if err != nil {
			log.Fatalf("failed to verify certificate : %v\n", err)
		}
		if 0 < i {
			ospool.AddCert(certificates[1])
		}
	}
	fmt.Println("証明書マジ正しい！")
	return certificates
}
func unpackECDiffieHellmanParam(packet []byte) ECDiffieHellmanParam {
	return ECDiffieHellmanParam{
		CurveType:          packet[0:1],
		NamedCurve:         packet[1:3],
		PubkeyLength:       packet[3:4],
		Pubkey:             readByteNum(packet, 4, 32),
		SignatureAlgorithm: packet[36:38],
		SignatureLength:    packet[38:40],
		Signature:          packet[40:],
	}
}

func unpackTLSHandshake(packet []byte) interface{} {
	var i interface{}

	switch packet[0] {
	case TypeServerHello:
		i = ServerHello{
			HandshakeType:     packet[0:1],
			Length:            packet[1:4],
			Version:           packet[4:6],
			Random:            packet[6:38],
			SessionID:         packet[38:39],
			CipherSuites:      packet[39:41],
			CompressionMethod: packet[41:42],
		}
		//fmt.Printf("ServerHello : %+v\n", i)
		//fmt.Printf("Cipher Suite is : %s\n", tls.CipherSuiteName(binary.BigEndian.Uint16(packet[39:41])))
	case TypeCertificate:
		i = ServerCertifiate{
			HandshakeType:      packet[0:1],
			Length:             packet[1:4],
			CertificatesLength: packet[4:7],
			Certificates:       readCertificates(packet[7:]),
		}
		//fmt.Printf("Certificate : %+v\n", i)
	case TypeServerKeyExchange:
		i = ServerKeyExchange{
			HandshakeType:               packet[0:1],
			Length:                      packet[1:4],
			ECDiffieHellmanServerParams: unpackECDiffieHellmanParam(packet[4:]),
		}
		//fmt.Printf("ServerKeyExchange : %+v\n", i)
	case TypeServerHelloDone:
		i = ServerHelloDone{
			HandshakeType: packet[0:1],
			Length:        packet[1:4],
		}
		//fmt.Printf("ServerHelloDone : %+v\n", i)
	}

	return i
}

func unpackTLSPacket(packet []byte) ([]TLSProtocol, []byte) {
	var protocols []TLSProtocol
	var protocolsByte []byte

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
			proto := TLSProtocol{
				RHeader:           rHeader,
				HandshakeProtocol: tls,
			}
			protocolsByte = append(protocolsByte, v[2:]...)
			protocols = append(protocols, proto)
		}
	}
	return protocols, protocolsByte
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

func startTLSHandshake(sendfd int, sendInfo TCPIP) (TCPHeader, error) {
	clienthelloPacket := NewTCPIP(sendInfo)

	destIp := iptobyte(sendInfo.DestIP)

	//recvfd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	syscall.Bind(sendfd, &syscall.SockaddrInet4{
		Port: 422779,
		Addr: [4]byte{byte(0xc0), byte(0xa8), byte(0x00), byte(0x14)},
	})
	// Client Helloを送る
	addr := setSockAddrInet4(destIp, int(sendInfo.DestPort))
	err := SendIPv4Socket(sendfd, clienthelloPacket, addr)
	if err != nil {
		return TCPHeader{}, fmt.Errorf("Send SYN packet err : %v", err)
	}
	fmt.Printf("Send TLS Client Hello to : %s\n", sendInfo.DestIP)

	var recvtcp TCPHeader
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
			recvtcp = parseTCP(recvBuf[20:])
			//if tcp.ControlFlags[0] == ACK {
			//	fmt.Printf("Recv ACK from %s\n", tcpip.DestIP)
			//	record, handshake := parseTLS(tcpip.Data, sumByteArr(ip.TotalPacketLength)-40)
			//	if record.ContentType[0] == HandShake && handshake.HandshakeType[0] == ServerHello {
			//		fmt.Printf("Recv ServerHello from %s\n", tcpip.DestIP)
			//		break
			//	}
			//} else
			if recvtcp.ControlFlags[0] == PSHACK {
				fmt.Printf("Recv PSHACK from %x\n", destIp)
				//fmt.Printf("ip Source %x\n", ip.SourceIPAddr)
				fmt.Printf("Recv TCP Length is %d\n", len(recvtcp.TCPData))

				unpackTLSPacket(recvtcp.TCPData)

				time.Sleep(10 * time.Millisecond)

				tcpLength := uint32(sumByteArr(ip.TotalPacketLength)) - 20
				tcpLength = tcpLength - uint32(recvtcp.HeaderLength[0]>>4<<2)
				ack := TCPIP{
					DestIP:    sendInfo.DestIP,
					DestPort:  sendInfo.DestPort,
					TcpFlag:   "ACK",
					SeqNumber: recvtcp.AcknowlegeNumber,
					AckNumber: calcSequenceNumber(recvtcp.SequenceNumber, tcpLength),
				}
				ackPacket := NewTCPIP(ack)
				// HTTPを受信したことに対してACKを送る
				SendIPv4Socket(sendfd, ackPacket, addr)
				//time.Sleep(100 * time.Millisecond)
				fmt.Println("Send ACK to server")
				break
			} else if recvtcp.ControlFlags[0] == FINACK { //FIN ACKであれば
				fmt.Println("recv FINACK from server")
				finack := TCPIP{
					DestIP:    sendInfo.DestIP,
					DestPort:  sendInfo.DestPort,
					TcpFlag:   "FINACK",
					SeqNumber: recvtcp.AcknowlegeNumber,
					AckNumber: calcSequenceNumber(recvtcp.SequenceNumber, 1),
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
	return recvtcp, nil
}
