package main

import (
	"bytes"
	"crypto/rsa"
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

const (
	LOCALIP   = "127.0.0.1"
	LOCALPORT = 8443
	// github.com
	GITHUBIP   = "13.114.40.48"
	GITHUBPORT = 443
)

func _main() {
	//var tlsinfo TLSInfo
	//tlsinfo.KeyBlock.ClientWriteIV = strtoByte("0bcd1746")
	//tlsinfo.KeyBlock.ClientWriteKey = strtoByte("475f58d5ca2aa6b36add62077ea4a340")
	//tlsinfo.ClientSequenceNum = 1
	//
	//appdata := []byte("hello\n")
	//fmt.Printf("appdata : %x\n", appdata)
	//header := NewTLSRecordHeader("AppDada", uint16(len(appdata)))
	//
	//encryptMessage(header, appdata, tlsinfo)

	decryptFinTest()

}

func main() {
	sock := NewSockStreemSocket()
	addr := setSockAddrInet4(iptobyte(LOCALIP), LOCALPORT)
	err := syscall.Connect(sock, &addr)
	if err != nil {
		log.Fatalf("connect err : %v\n", err)
	}

	var tlsinfo TLSInfo
	var hello ClientHello
	var hellobyte []byte
	tlsinfo.MasterSecretInfo.ClientRandom, hellobyte = hello.NewRSAClientHello()
	syscall.Write(sock, hellobyte)

	fmt.Printf("client random : %x\n", tlsinfo.MasterSecretInfo.ClientRandom)

	//tlsinfo.MasterSecretInfo.ClientRandom = noRandomByte(32)

	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, hellobyte[5:]...)

	var tlsproto []TLSProtocol
	var tlsbyte []byte

	for {
		recvBuf := make([]byte, 1500)
		_, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// ServerHello, Certificates, ServerHelloDoneをパース
		tlsproto, tlsbyte = unpackTLSPacket(recvBuf)
		break
	}

	// ServerHello, Certificates, ServerHelloDoneをappend
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, tlsbyte...)

	var pubkey *rsa.PublicKey
	for _, v := range tlsproto {
		switch proto := v.HandshakeProtocol.(type) {
		case ServerHello:
			// ServerHelloからrandomを取り出す
			tlsinfo.MasterSecretInfo.ServerRandom = proto.Random
		case ServerCertificate:
			_, ok := proto.Certificates[0].PublicKey.(*rsa.PublicKey)
			if !ok {
				log.Fatalf("cast pubkey err : %v\n", ok)
			}
			// Certificateからサーバの公開鍵を取り出す
			pubkey = proto.Certificates[0].PublicKey.(*rsa.PublicKey)
		}
	}

	fmt.Printf("ClientRandom : %x\n", tlsinfo.MasterSecretInfo.ClientRandom)
	fmt.Printf("ServerRandom : %x\n", tlsinfo.MasterSecretInfo.ServerRandom)

	// premaster secretをサーバの公開鍵で暗号化する
	// 暗号化したらTLSのMessage形式にしてClientKeyExchangeを作る
	var clientKeyExchange ClientKeyExchange
	var clientKeyExchangeBytes []byte
	clientKeyExchangeBytes, tlsinfo.MasterSecretInfo.PreMasterSecret = clientKeyExchange.NewClientKeyExchange(pubkey)
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, clientKeyExchangeBytes[5:]...)

	// ChangeCipherSpecのMessageを作る
	changeCipher := NewChangeCipherSpec()

	var verifyData []byte

	verifyData, tlsinfo.KeyBlock, tlsinfo.MasterSecretInfo.MasterSecret = createVerifyData(tlsinfo.MasterSecretInfo, CLientFinishedLabel, tlsinfo.Handshakemessages)
	finMessage := []byte{HandshakeTypeFinished}
	finMessage = append(finMessage, uintTo3byte(uint32(len(verifyData)))...)
	finMessage = append(finMessage, verifyData...)
	fmt.Printf("finMessage : %x\n", finMessage)

	// 送ったClient finishedを入れる、Serverからのfinishedと照合するため
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, finMessage...)

	rheader := NewTLSRecordHeader("Handshake", uint16(len(finMessage)))
	encryptFin := encryptClientMessage(rheader, finMessage, tlsinfo)

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
			serverfin := decryptServerMessage(recvBuf[6:51], tlsinfo, ContentTypeHandShake)
			verify := createServerVerifyData(tlsinfo.MasterSecretInfo.MasterSecret, tlsinfo.Handshakemessages)

			if bytes.Equal(serverfin[4:], verify) {
				fmt.Printf("server fin : %x, client verify : %x, verify is ok !!\n", serverfin[4:], verify)
			}
		}
		break
	}

	//送って受け取ったらシーケンスを増やす
	tlsinfo.ClientSequenceNum++

	req := NewHttpGetRequest("/", fmt.Sprintf("%s:%d", LOCALIP, LOCALPORT))
	reqbyte := req.reqtoByteArr(req)

	//appdata := []byte("hello\n")
	fmt.Printf("appdata : %x\n", reqbyte)
	encAppdata := encryptClientMessage(NewTLSRecordHeader("AppDada", uint16(len(reqbyte))), reqbyte, tlsinfo)

	syscall.Write(sock, encAppdata)
	time.Sleep(10 * time.Millisecond)

	for {
		recvBuf := make([]byte, 1500)
		_, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// 0byteがApplication Dataであるか
		if bytes.HasPrefix(recvBuf, []byte{ContentTypeApplicationData}) {
			// 6byteからServerFinishedMessageになるのでそれをunpackする
			length := binary.BigEndian.Uint16(recvBuf[3:5])
			serverappdata := decryptServerMessage(recvBuf[0:length+5], tlsinfo, ContentTypeApplicationData)
			//fmt.Printf("app data from server : %x\n", appdata)
			fmt.Printf("app data from server : %s\n", string(serverappdata))
		}
		break
	}
	tlsinfo.ClientSequenceNum++

	encryptAlert := encryptClientMessage(NewTLSRecordHeader("Alert", 2), []byte{0x01, 0x00}, tlsinfo)
	syscall.Write(sock, encryptAlert)
	time.Sleep(10 * time.Millisecond)
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
	_ = hello

	clienthello := TCPIP{
		DestIP:    dest,
		DestPort:  port,
		TcpFlag:   "PSHACK",
		SeqNumber: ack.SeqNumber,
		AckNumber: ack.AckNumber,
		//Data:      hello.NewRSAClientHello(),
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
