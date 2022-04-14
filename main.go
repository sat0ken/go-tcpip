package main

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"github.com/k0kubun/pp/v3"
	"log"
	"syscall"
	"time"
)

// おまじない
// sudo sh -c 'echo 3 > /proc/sys/net/ipv4/tcp_retries2'
// sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

const (
	LOCALIP = "127.0.0.1"
	// github.com
	GITHUBIP   = "13.114.40.48"
	LOCALPORT  = 10443
	GITHUBPORT = 443
)

func _() {
	//decryptFinTest()
	//b := strtoByte("16030300280000000000000000427ee17499822aea9bffa09c420f78630268de7926f162002809b8ad1f5096e3")
	//decryptServerFinMessage(b)
	var premasterByte []byte
	premasterByte = append(premasterByte, TLS1_2...)
	premasterByte = append(premasterByte, noRandomByte(46)...)

	var random []byte
	random = append(random, noRandomByte(32)...)
	random = append(random, noRandomByte(32)...)

	// master secretを作成する
	master := prf(premasterByte, MasterSecretLable, random, 48)

	var handshake_message []byte
	handshake_message = append(handshake_message, strtoByte(clientHellostr)...)
	handshake_message = append(handshake_message, strtoByte(serverHellostr)...)
	handshake_message = append(handshake_message, strtoByte(serverCertificatestr)...)
	handshake_message = append(handshake_message, strtoByte(serveHelloDonestr)...)
	handshake_message = append(handshake_message, strtoByte(clientKeyExchagestr)...)
	handshake_message = append(handshake_message, strtoByte(clientFinishstr)...)

	fmt.Printf("%x\n", handshake_message)

	fmt.Printf("%x\n", createServerVerifyData(master, handshake_message))
	//createFinishTest()
}

func main() {
	sock := NewSockStreemSocket()
	addr := setSockAddrInet4(iptobyte(LOCALIP), LOCALPORT)
	err := syscall.Connect(sock, &addr)
	if err != nil {
		log.Fatalf("connect err : %v\n", err)
	}
	fmt.Println("connect success !!")
	var hello ClientHello
	hellobyte := hello.NewRSAClientHello()
	syscall.Write(sock, hellobyte)

	var handshake_messages []byte
	handshake_messages = append(handshake_messages, hellobyte[5:]...)

	var tlsproto []TLSProtocol
	var tlsbyte []byte

	for {
		recvBuf := make([]byte, 1500)
		_, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		tlsproto, tlsbyte = unpackTLSPacket(recvBuf)
		break
	}
	handshake_messages = append(handshake_messages, tlsbyte...)

	var serverRandom []byte
	var pubkey *rsa.PublicKey

	for _, v := range tlsproto {
		switch proto := v.HandshakeProtocol.(type) {
		case ServerHello:
			serverRandom = proto.Random
		case ServerCertificate:
			_, ok := proto.Certificates[0].PublicKey.(*rsa.PublicKey)
			if !ok {
				log.Fatalf("cast pubkey err : %v\n", ok)
			}
			pubkey = proto.Certificates[0].PublicKey.(*rsa.PublicKey)
		}
	}

	var clientKeyExchange ClientKeyExchange
	clientKeyExchangeBytes, premasterBytes := clientKeyExchange.NewClientKeyExchange(pubkey)
	handshake_messages = append(handshake_messages, clientKeyExchangeBytes[5:]...)

	changeCipher := NewChangeCipherSpec()

	master := MasterSecret{
		PreMasterSecret: premasterBytes,
		ServerRandom:    serverRandom,
		ClientRandom:    noRandomByte(32),
	}

	//fmt.Printf("handshake_message : %x\n", handshake_messages)

	verifyData, keyblock, masterByte := createVerifyData(master, CLientFinished, handshake_messages)
	finMessage := []byte{HandshakeTypeFinished}
	finMessage = append(finMessage, uintTo3byte(uint32(len(verifyData)))...)
	finMessage = append(finMessage, verifyData...)
	fmt.Printf("finMessage : %x\n", finMessage)

	// 送ったClient finishedを入れる、Serverからのfinishedと照合するため
	handshake_messages = append(handshake_messages, finMessage...)

	rheader := TLSRecordHeader{
		ContentType:     []byte{ContentTypeHandShake},
		ProtocolVersion: TLS1_2,
		Length:          uintTo2byte(uint16(len(finMessage))),
	}

	encryptFin := encryptMessage(rheader, keyblock.ClientWriteIV, finMessage, keyblock.ClientWriteKey)

	var all []byte
	all = append(all, clientKeyExchangeBytes...)
	all = append(all, changeCipher...)
	all = append(all, encryptFin...)

	syscall.Write(sock, all)
	
	for {
		recvBuf := make([]byte, 1500)
		_, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// 0byteがChangeCipherSpecであるか
		if bytes.HasPrefix(recvBuf, []byte{HandshakeTypeChangeCipherSpec}) {
			// 6byteからServerFinishedMessageになるのでそれをunpackする
			serverfin := decryptServerFinMessage(recvBuf[6:51], keyblock)
			verify := createServerVerifyData(masterByte, handshake_messages)

			if bytes.Equal(serverfin[4:], verify) {
				fmt.Printf("server fin : %x, client verify : %x, verify is ok !!\n", serverfin[4:], verify)
			}
		}
		break
	}

	syscall.Close(sock)
}

func _() {

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

	var handshake_messages []byte
	handshake_messages = append(handshake_messages, clienthello.Data[5:]...)

	// ClientHelloを送りServerHelloを受信する
	err = starFromClientHello(sendfd, clienthello)
	if err != nil {
		log.Fatal(err)
	}
	//
	//handshake_messages = append(handshake_messages, serverhello.TLSProcotocolBytes...)
	//copy(serverhello.TLSProcotocolBytes, handshake_messages)
	//
	//time.Sleep(time.Millisecond * 10)
	//
	//serverhello.ClientHelloRandom = hello.Random
	//sendClientKeyExchangeToFinish(sendfd, serverhello)

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
