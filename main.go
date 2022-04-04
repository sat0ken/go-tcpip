package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/k0kubun/pp/v3"
	"log"
	"syscall"
	"time"
)

// おまじない
// sudo sh -c 'echo 3 > /proc/sys/net/ipv4/tcp_retries2'
// sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

//func main() {
//	synack_finack()
//}

const (
	LOCALIP = "127.0.0.1"
	// github.com
	GITHUBIP   = "13.114.40.48"
	LOCALPORT  = 10443
	GITHUBPORT = 443
)

func __main() {
	premaster := randomByte(48)
	clientRandom := randomByte(32)
	serverRandom := randomByte(32)

	var clientServerRandomByte []byte
	clientServerRandomByte = append(clientServerRandomByte, clientRandom...)
	clientServerRandomByte = append(clientServerRandomByte, serverRandom...)

	result := createMasterSecret(premaster, clientServerRandomByte)
	result2 := createMasterSecret(premaster, clientServerRandomByte)
	fmt.Printf("%x\n", result)
	fmt.Printf("%x\n", result2)

}

func ___main() {
	serverTLS, protoBytes := unpackTLSPacket(rsaByte)
	for _, v := range serverTLS {
		switch proto := v.HandshakeProtocol.(type) {
		case ServerHello:
			fmt.Printf("Cipher Suite is : %s\n", tls.CipherSuiteName(binary.BigEndian.Uint16(proto.CipherSuites)))
		case ServerCertifiate:
			fmt.Printf("Pubkey type is %T\n", proto.Certificates[0].PublicKey)
			fmt.Println(proto.Certificates[0].PublicKey)
		case ServerHelloDone:
			fmt.Println("ServerHelloDone")
		}
	}
	_ = protoBytes
}

func main() {

	dest := LOCALIP
	var port uint16 = LOCALPORT

	syn := TCPIP{
		DestIP:   dest,
		DestPort: port,
		TcpFlag:  "SYN",
	}
	sendfd := NewTCPSocket()
	defer syscall.Close(sendfd)
	fmt.Printf("Send SYN packet to %s\n", dest)
	ack, err := startTCPConnection(sendfd, syn)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("TCP Connection is success!!\n\n")
	time.Sleep(10 * time.Millisecond)

	//serverPacket := make(chan IPTCPTLS)

	var hello ClientHello

	clienthello := TCPIP{
		DestIP:    dest,
		DestPort:  port,
		TcpFlag:   "PSHACK",
		SeqNumber: ack.SeqNumber,
		AckNumber: ack.AckNumber,
		Data:      hello.NewRSAClientHello(),
	}

	// ClientHelloを送りServerHelloを受信する
	serverhello, err := starFromClientHello(sendfd, clienthello)
	if err != nil {
		log.Fatal(err)
	}

	//pp.Println(serverhello)

	serverhello.ClientHelloRandom = hello.Random
	sendClientKeyExchangeToFinish(sendfd, serverhello)

	for {
		recvBuf := make([]byte, 65535)
		_, _, err := syscall.Recvfrom(sendfd, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// IPヘッダをUnpackする
		ip := parseIP(recvBuf[0:20])
		if bytes.Equal(ip.Protocol, []byte{0x06}) && bytes.Equal(ip.SourceIPAddr, iptobyte(dest)) {
			recvtcp := parseTCP(recvBuf[20:])
			if bytes.Equal(recvtcp.ControlFlags, []byte{ACK}) && bytes.Equal(recvtcp.SourcePort, uintTo2byte(LOCALPORT)) {
				//pp.Println(recvtcp)
				fmt.Printf("Recv Finished message ACK from %s\n", dest)
			} else if bytes.Equal(recvtcp.ControlFlags, []byte{PSHACK}) && bytes.Equal(recvtcp.SourcePort, uintTo2byte(LOCALPORT)) {
				fmt.Printf("Recv Finished message PSHACK from %s\n", dest)
				pp.Println(recvtcp)
			}
		}
	}

	//fin := TCPIP{
	//	DestIP:    dest,
	//	DestPort:  port,
	//	TcpFlag:   "PSHACK",
	//	SeqNumber: serverhello.TCPHeader.SequenceNumber,
	//	AckNumber: serverhello.TCPHeader.AcknowlegeNumber,
	//	Data:      message,
	//}
	//
	//fmt.Printf("Send ClientKeyExchange packet to %s\n", dest)
	//_, err = startTCPConnection(sendfd, fin)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//fmt.Printf("TCP Connection Close is success!!\n")
}
