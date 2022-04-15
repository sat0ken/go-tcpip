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

func _() {
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

	buf := strtoByte("16030300510200004d0303312c10799a53725901e6eef223378bbdd1bbdbcdab5d3856444f574e4752440120eea9d190349cd40a738e06582019d47037ad53e4d1bc57006b981fa4da7ad1d4009c000005ff0100010016030304250b00042100041e00041b308204173082027fa003020102020f059ac2235f09f0f8066c1544ed1a6e300d06092a864886f70d01010b0500305b311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131183016060355040b0c0f7361746f6b656e407361746f6b656e311f301d06035504030c166d6b63657274207361746f6b656e407361746f6b656e301e170d3232303430323032343930385a170d3234303730323032343930385a304331273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531183016060355040b0c0f7361746f6b656e407361746f6b656e30820122300d06092a864886f70d01010105000382010f003082010a0282010100c708440e307a7e8c40d686be0a258b3bd264ec025cfa651e16bcf22cd11bc44fb9bb5e29e361bf0612727338625783200297f3f5e7bc83abff25f4b2a3783f8ed6bfdff95b1d50490f990125e7a49cfac35de22eb69a1c438184780c71d880805106d9bdcbca5b53183615d9b450123517bf9dfa4e907c2e23abff604abbf97ec33df0154f7a0c6c0eaef7740bc14f810f47db904804b92a7db37f1bff460b486f9f8bc79f72e099fb0757b0e4472f28019688c5a47590ff1ec077f7754227104cfaa9674074c4c2f9458c7d6745609ad5db221a473edb3ed9032713228a278f3d0b81ec6585b9f3b7787889cf3dd11194cf7cb409bea503582c7b285490aa570203010001a370306e300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301f0603551d2304183016801404d98d95143b1c115acc6ca986000253e9c9feb430260603551d11041f301d820a6d792d746c732e636f6d82096c6f63616c686f737487047f000001300d06092a864886f70d01010b0500038201810027d1655962c4f648a79735dfc31461db16b92f2a849d37886e353ee67a94d4d0f85b8c20e2207180d37af551a0a040cac73e5d7cf474b78e6d819afa543c334b2a949f3ef5f45f33e8c07f0e43e4d5f94f11c33d726d32458b87c82bbba12fa1f97aebdddcf5046c450fcef30e08e7bc371d300a0c48f91fe4b1b51de002481acdb15532596974983be65e4f1299cd2a43930c7de9d3c4dcb9f6c94f4f5047487694d4de4e6c08d3a737c3b40a943710c385264bb3b3a40aae1f66d4b54a458a6d5f4691b48112aae3ef6bbb96c002c4d4e8598319baf0fc1b3bdc895e1559f2b5f2748c61998ed182bb7ed43ad4cfd17b44953e571cfc2ccaf632cd1569d43d3fb7262da4c023b0e10417edafeb03d0df59e797cfa5ec58dc9ccc10d868f39dee0a6af29736b7f1d1ba5506fcb42ca99397a5f4bad7fa34e5470d1606fa99f65a56ca23afa9ae6d712d8030885bc69ed5fcff463aec982585965ca7b3573540fc3b4685cb3e4c287c1632d4aa9860b6e06a963151a7285c46bd8988df1943ee16030300040e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	b := bytes.Split(buf, []byte{0x16, 0x03, 0x03})

	copy(b, b[1:len(b)-1])

	for _, v := range b {
		fmt.Println(v[2])
		fmt.Printf("%x\n", v)
	}

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

	// handshakeメッセージはverify_data作成のために保存しておく
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
		tlsproto, tlsbyte = parseTLSPacket(recvBuf)
		break
	}

	// parseしたServerHello, Certificates, ServerHelloDoneをappend
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

	// ClientKeyexchange, ChangeCipehrspec, ClientFinsihedを全部まとめる
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
