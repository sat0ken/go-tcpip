package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"log"
	"syscall"
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

func main() {

	// private key (32 octets): 49 af 42 ba 7f 79 94 85 2d 71 3e f2 78 4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05
	clientPrivateKey, _ := hex.DecodeString("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005")
	// public key (32 octets): c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f
	serverPublickKey, _ := hex.DecodeString("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")

	// {client} construct a ClientHello handshake message:
	clienthello := "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"
	// {server} construct a ServerHello handshake message:
	sererhello := "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"

	clientserverhello, _ := hex.DecodeString(clienthello + sererhello)

	sharedkey, _ := curve25519.X25519(clientPrivateKey, serverPublickKey)
	keyscheduleToMasterSecret(sharedkey, clientserverhello)
}

func _() {
	// ClientHello
	hello := "010000ba03030000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000213030100006f000500050100000000000a00040002001d000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000120000002b0003020304003300260024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74"
	// ServerHello
	hello += "0200007603030000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000130300002e002b0002030400330024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74"
	// EncryptedExtensions
	hello += "080000020000"
	// Certificate
	hello += "0b0004240000042000041b308204173082027fa003020102020f059ac2235f09f0f8066c1544ed1a6e300d06092a864886f70d01010b0500305b311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131183016060355040b0c0f7361746f6b656e407361746f6b656e311f301d06035504030c166d6b63657274207361746f6b656e407361746f6b656e301e170d3232303430323032343930385a170d3234303730323032343930385a304331273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531183016060355040b0c0f7361746f6b656e407361746f6b656e30820122300d06092a864886f70d01010105000382010f003082010a0282010100c708440e307a7e8c40d686be0a258b3bd264ec025cfa651e16bcf22cd11bc44fb9bb5e29e361bf0612727338625783200297f3f5e7bc83abff25f4b2a3783f8ed6bfdff95b1d50490f990125e7a49cfac35de22eb69a1c438184780c71d880805106d9bdcbca5b53183615d9b450123517bf9dfa4e907c2e23abff604abbf97ec33df0154f7a0c6c0eaef7740bc14f810f47db904804b92a7db37f1bff460b486f9f8bc79f72e099fb0757b0e4472f28019688c5a47590ff1ec077f7754227104cfaa9674074c4c2f9458c7d6745609ad5db221a473edb3ed9032713228a278f3d0b81ec6585b9f3b7787889cf3dd11194cf7cb409bea503582c7b285490aa570203010001a370306e300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301f0603551d2304183016801404d98d95143b1c115acc6ca986000253e9c9feb430260603551d11041f301d820a6d792d746c732e636f6d82096c6f63616c686f737487047f000001300d06092a864886f70d01010b0500038201810027d1655962c4f648a79735dfc31461db16b92f2a849d37886e353ee67a94d4d0f85b8c20e2207180d37af551a0a040cac73e5d7cf474b78e6d819afa543c334b2a949f3ef5f45f33e8c07f0e43e4d5f94f11c33d726d32458b87c82bbba12fa1f97aebdddcf5046c450fcef30e08e7bc371d300a0c48f91fe4b1b51de002481acdb15532596974983be65e4f1299cd2a43930c7de9d3c4dcb9f6c94f4f5047487694d4de4e6c08d3a737c3b40a943710c385264bb3b3a40aae1f66d4b54a458a6d5f4691b48112aae3ef6bbb96c002c4d4e8598319baf0fc1b3bdc895e1559f2b5f2748c61998ed182bb7ed43ad4cfd17b44953e571cfc2ccaf632cd1569d43d3fb7262da4c023b0e10417edafeb03d0df59e797cfa5ec58dc9ccc10d868f39dee0a6af29736b7f1d1ba5506fcb42ca99397a5f4bad7fa34e5470d1606fa99f65a56ca23afa9ae6d712d8030885bc69ed5fcff463aec982585965ca7b3573540fc3b4685cb3e4c287c1632d4aa9860b6e06a963151a7285c46bd8988df1943ee0000"
	// CertificateVerify
	hello += "0f00010408040100c3bce6e5becc22190bc1c2a6d228cca3ea8dda8a6bd350526c540cd11423b942f7e0d33630c651f1a33c10301a84ce5844ac1b98b3373de2100998f993e6237697ee5bdde8a8278020efd6affd2040cc4bbbd1e4266f0a7592f2cde0c3409d72a9bef153f2c9cd23e088682bf9ccf238d07254be441a3855691019970ab001ea9c93948aa06c31318265811ec88d949b30172abdbef28e3361d7ad9791ba7c969c765f3e8190bb6fb30627bc48b616fd8063ab3f2484aa9f5004fd93d9a81f16ce2db4d3be2eff53a0744c6114367776807f078ca03847dc17c33a6fe65f24c25bb0094013e90cc5b8e07b928870c318f4983a31a79f2fb830e6f69c6af7c36c"
	// Serverfinished
	//hello += "1400002022a5998b36ef577aab9e06bb6ca02980db8b75b10c086189e501cab08b6e4e54"

	hashed_message := writeHash(strtoByte(hello))
	fmt.Printf("hashed_message %x\n", hashed_message)
	key := strtoByte("05c01ce1d06ce04aaafd0ceb8c3413b7fb4f5e42843dd9b4022c21a27c46032b")
	mac := hmac.New(sha256.New, key)
	mac.Write(hashed_message)
	verifydata := mac.Sum(nil)
	fmt.Printf("Server Verify data is %x\n", verifydata)
}

func _() {

	sock := NewSockStreemSocket()
	addr := setSockAddrInet4(iptobyte(LOCALIP), LOCALPORT)
	err := syscall.Connect(sock, &addr)
	if err != nil {
		log.Fatalf("connect err : %v\n", err)
	}

	var hello ClientHello
	// ClientHelloメッセージを作成
	tlsinfo, hellobyte := hello.NewClientHello(TLS1_3)
	// メッセージを送信
	syscall.Write(sock, hellobyte)

	var packet []byte
	// ServerHello, ChangeCipherSpec, EncryptedExtensions, Certificate, CertificateVerify, Finishedを受信する
	for {
		recvBuf := make([]byte, 2000)
		n, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		packet = recvBuf[0:n]
		break
	}

	// read ServerHello
	length := binary.BigEndian.Uint16(packet[3:5]) + 5
	serverhello := parseTLSHandshake(packet[5:length], TLS1_3).(ServerHello)
	serverkeyshare := serverhello.TLSExtensions[1].Value.(map[string]interface{})["KeyExchange"]

	// Serverhelloをmessageに入れておく
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, packet[5:length]...)
	tlsinfo.State = ContentTypeHandShake

	fmt.Printf("server key share is %x\n", serverkeyshare.([]byte))
	//クライアントの秘密鍵とサーバの公開鍵で共通鍵を生成する
	sharedkey, _ := curve25519.X25519(tlsinfo.ECDHEKeys.privateKey, serverkeyshare.([]byte))
	fmt.Printf("sharedkey is %x\n", sharedkey)

	tlsinfo.KeyBlockTLS13 = keyscheduleToMasterSecret(sharedkey, tlsinfo.Handshakemessages)

	copy(packet, packet[length:])

	// read ChangeCipherSpec
	changecipherspec := packet[0:6]
	fmt.Printf("read ChangeCipherSpec is %x, これから暗号化するんやでー\n", changecipherspec)
	copy(packet, packet[6:])

	hanshake := bytes.Split(packet, []byte{0x17, 0x03, 0x03})
	var pubkey *rsa.PublicKey
exit_loop:
	for _, v := range hanshake {
		if len(v) != 0 {
			v = append([]byte{0x17, 0x03, 0x03}, v...)
			length := binary.BigEndian.Uint16(v[3:5]) + 5

			plaintext := decryptChacha20(v[0:length], tlsinfo)
			i := parseTLSHandshake(plaintext[0:len(plaintext)-1], TLS1_3)

			switch proto := i.(type) {
			case ServerCertificate:
				pubkey = proto.Certificates[0].PublicKey.(*rsa.PublicKey)
			case CertificateVerify:
				verifyServerCertificate(pubkey, proto.Signature, tlsinfo.Handshakemessages)
			case FinishedMessage:
				key := tlsinfo.KeyBlockTLS13.serverFinishedKey
				mac := hmac.New(sha256.New, key)
				mac.Write(writeHash(tlsinfo.Handshakemessages))
				verifydata := mac.Sum(nil)
				if bytes.Equal(verifydata, plaintext[4:len(plaintext)-1]) {
					fmt.Println("Server Verify data is correct !!")
					tlsinfo.ServerHandshakeSeq++
					tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, plaintext[0:len(plaintext)-1]...)
					break exit_loop
				} else {
					// 4.4.4. Finished 本当はdecrypt_errorを送る必要があるのでほんとはだめ
					log.Fatalf("Server Verify data is incorrect! Handshake is stop!")
				}
			}

			tlsinfo.ServerHandshakeSeq++
			tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, plaintext[0:len(plaintext)-1]...)

		}
	}

	// App用のキーを作る
	tlsinfo = keyscheduleToAppTraffic(tlsinfo)

	// ChangeCipherSpecメッセージを作る
	changeCipher := NewChangeCipherSpec()

	key := tlsinfo.KeyBlockTLS13.clientFinishedKey
	mac := hmac.New(sha256.New, key)
	mac.Write(writeHash(tlsinfo.Handshakemessages))
	verifydata := mac.Sum(nil)

	finMessage := []byte{HandshakeTypeFinished}
	finMessage = append(finMessage, uintTo3byte(uint32(len(verifydata)))...)
	finMessage = append(finMessage, verifydata...)
	finMessage = append(finMessage, ContentTypeHandShake)

	fmt.Printf("fin message %x\n", finMessage)

	encryptFinMessage := encryptChacha20(finMessage, tlsinfo)
	fmt.Printf("fin message %x\n", encryptFinMessage)

	var all []byte
	all = append(all, changeCipher...)
	all = append(all, encryptFinMessage...)

	// Finished messageを送る
	syscall.Write(sock, all)
	fmt.Println("send finished message")

	tlsinfo.State = ContentTypeApplicationData
	//appData := []byte("hello\n")
	// HTTPリクエストを作成する
	req := NewHttpGetRequest("/", fmt.Sprintf("%s:%d", LOCALIP, LOCALPORT))
	appData := req.reqtoByteArr(req)
	appData = append(appData, ContentTypeApplicationData)
	encAppData := encryptChacha20(appData, tlsinfo)

	// HTTPSリクエストを送る
	syscall.Write(sock, encAppData)
	tlsinfo.ClientAppSeq++

	fmt.Println("send Application data")
	for {
		recvBuf := make([]byte, 2000)
		_, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		length := binary.BigEndian.Uint16(recvBuf[3:5])
		plaintext := decryptChacha20(recvBuf[0:length+5], tlsinfo)
		// Alert(Close notify)が来たらbreakして終了
		if bytes.Equal(plaintext[len(plaintext)-1:], []byte{ContentTypeAlert}) {
			break
		} else if bytes.Equal(plaintext[len(plaintext)-1:], []byte{ContentTypeApplicationData}) {
			fmt.Printf("\nplaintext is %s\n", string(plaintext[0:len(plaintext)-1]))
			//break
		}
		tlsinfo.ServerAppSeq++
	}

	//closeNotify := encryptChacha20(strtoByte("010015"), tlsinfo)
	//// Close notifyで接続終了する
	//syscall.Write(sock, closeNotify)
	//fmt.Println("send close notify")
	//for {
	//	recvBuf := make([]byte, 2000)
	//	n, _, err := syscall.Recvfrom(sock, recvBuf, 0)
	//	if err != nil {
	//		log.Fatalf("read err : %v", err)
	//	}
	//	fmt.Printf("%x\n", recvBuf[0:n])
	//	break
	//}

}
