package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
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
	LOCALPORT = 10443
	// github.com
	GITHUBIP   = "13.114.40.48"
	GITHUBPORT = 443
)

func _() {
	// ClientHello
	hello := "010000c6030300000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000008009c13011302130301000075000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000120000002b0003020304003300260024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74"
	// ServerHello
	hello += "0200007603030000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000130300002e002b0002030400330024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74"
	// EncryptedExtensions
	hello += "080000020000"
	// Certificate
	hello += "0b0004240000042000041b308204173082027fa003020102020f059ac2235f09f0f8066c1544ed1a6e300d06092a864886f70d01010b0500305b311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131183016060355040b0c0f7361746f6b656e407361746f6b656e311f301d06035504030c166d6b63657274207361746f6b656e407361746f6b656e301e170d3232303430323032343930385a170d3234303730323032343930385a304331273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531183016060355040b0c0f7361746f6b656e407361746f6b656e30820122300d06092a864886f70d01010105000382010f003082010a0282010100c708440e307a7e8c40d686be0a258b3bd264ec025cfa651e16bcf22cd11bc44fb9bb5e29e361bf0612727338625783200297f3f5e7bc83abff25f4b2a3783f8ed6bfdff95b1d50490f990125e7a49cfac35de22eb69a1c438184780c71d880805106d9bdcbca5b53183615d9b450123517bf9dfa4e907c2e23abff604abbf97ec33df0154f7a0c6c0eaef7740bc14f810f47db904804b92a7db37f1bff460b486f9f8bc79f72e099fb0757b0e4472f28019688c5a47590ff1ec077f7754227104cfaa9674074c4c2f9458c7d6745609ad5db221a473edb3ed9032713228a278f3d0b81ec6585b9f3b7787889cf3dd11194cf7cb409bea503582c7b285490aa570203010001a370306e300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301f0603551d2304183016801404d98d95143b1c115acc6ca986000253e9c9feb430260603551d11041f301d820a6d792d746c732e636f6d82096c6f63616c686f737487047f000001300d06092a864886f70d01010b0500038201810027d1655962c4f648a79735dfc31461db16b92f2a849d37886e353ee67a94d4d0f85b8c20e2207180d37af551a0a040cac73e5d7cf474b78e6d819afa543c334b2a949f3ef5f45f33e8c07f0e43e4d5f94f11c33d726d32458b87c82bbba12fa1f97aebdddcf5046c450fcef30e08e7bc371d300a0c48f91fe4b1b51de002481acdb15532596974983be65e4f1299cd2a43930c7de9d3c4dcb9f6c94f4f5047487694d4de4e6c08d3a737c3b40a943710c385264bb3b3a40aae1f66d4b54a458a6d5f4691b48112aae3ef6bbb96c002c4d4e8598319baf0fc1b3bdc895e1559f2b5f2748c61998ed182bb7ed43ad4cfd17b44953e571cfc2ccaf632cd1569d43d3fb7262da4c023b0e10417edafeb03d0df59e797cfa5ec58dc9ccc10d868f39dee0a6af29736b7f1d1ba5506fcb42ca99397a5f4bad7fa34e5470d1606fa99f65a56ca23afa9ae6d712d8030885bc69ed5fcff463aec982585965ca7b3573540fc3b4685cb3e4c287c1632d4aa9860b6e06a963151a7285c46bd8988df1943ee0000"
	// CertificateVerify
	hello += "0f000104080401006310b19bc8c05f9d36b9fe7416c554b8a01e00b430c8572cc34ac6d611048555293c61f44edc9b906b93f22938e4229c65020916ee10d4a33817066d4b1572b9057ceb35a862046c802d1f02300b53890d4950fc716df59cbd58a907cdb584bf0be47a2d4b135e99b8fae8c1a6ce9f4e703549c37c0ce8b7844d3f81b9a064e52e2ab72ab8656924162f4f389ef518a0a795d1c25981fd524bd70d9bdd2d8051a88ee31c18f3693ef39ec034af6c9195a8a40eab3b399a5d9322a23e45c85e874e829df5ef5ce4ad208359c2bd8f6fb650e45668e06c0375063d27642808dc0c4586ec6562e2298497e0dbb91189cce11c04593572a30fb86a8698c1992c4074"
	// Serverfinished
	hello += "1400002022a5998b36ef577aab9e06bb6ca02980db8b75b10c086189e501cab08b6e4e54"

	hasher := sha256.New()
	hasher.Write(strtoByte(hello))

	fmt.Printf("%x\n", hasher.Sum(nil))
	key := strtoByte("84a9a6d9292516517320b50e5dbf90f638585940985ecc7c5266940d6ef8ff03")
	mac := hmac.New(sha256.New, key)
	mac.Write(hasher.Sum(nil))

	fmt.Printf("fin message %x\n", mac.Sum(nil))

	var tlsinfo TLSInfo
	tlsinfo.State = ContentTypeHandShake
	tlsinfo.KeyBlockTLS13.clientHandshakeKey = strtoByte("a990a0db836e8b4c813abbdfda673d829350ab37fad72a7000e1f78580ccd69d")
	tlsinfo.KeyBlockTLS13.clientHandshakeIV = strtoByte("7e2fad51ebfcc379edaf2e6a")

	finMessage := []byte{HandshakeTypeFinished}
	finMessage = append(finMessage, uintTo3byte(uint32(len(mac.Sum(nil))))...)
	finMessage = append(finMessage, mac.Sum(nil)...)
	finMessage = append(finMessage, ContentTypeHandShake)

	fmt.Printf("fin message %x\n", finMessage)

	encryptFinMessage := encryptChacha20(finMessage, tlsinfo)
	fmt.Printf("fin message %x\n", encryptFinMessage)

	tlsinfo.KeyBlockTLS13.clientAppKey = strtoByte("c022ca0fa9de354be2d6c414aac72c0c3223677e72067642f201f71c7641d518")
	tlsinfo.KeyBlockTLS13.clientAppIV = strtoByte("bed48d46028b5d5ff48a0b01")

	tlsinfo.State = ContentTypeApplicationData

	closeNotify := encryptChacha20(strtoByte("010015"), tlsinfo)
	fmt.Printf("closeNotify %x\n", closeNotify)

	record := strtoByte("1503030002")
	payload := strtoByte("0100")

	record = append(record, payload...)
	fmt.Printf("record %x\n", record)

	// Encrypt the actual ContentType and replace the plaintext one.
	record = append(record, record[0])
	fmt.Printf("record %x\n", record)
	//record[0] = byte(recordTypeApplicationData)
	//
	//n := len(payload) + 1 + c.Overhead()
	//record[3] = byte(n >> 8)
	//record[4] = byte(n)

}

func main() {
	//clientCert := readClientCertificate()

	sock := NewSockStreemSocket()
	addr := setSockAddrInet4(iptobyte(LOCALIP), LOCALPORT)
	err := syscall.Connect(sock, &addr)
	if err != nil {
		log.Fatalf("connect err : %v\n", err)
	}

	var hello ClientHello
	tlsinfo, hellobyte := hello.NewClientHello(TLS1_3)
	syscall.Write(sock, hellobyte)

	//fmt.Printf("client random : %x\n", tlsinfo.MasterSecretInfo.ClientRandom)

	//var tlsproto []TLSProtocol
	//var tlsbyte []byte
	var packet []byte

	for {
		recvBuf := make([]byte, 2000)
		n, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		packet = recvBuf[0:n]
		break
	}

	//fmt.Printf("recv buf is %x\n", packet)

	// read ServerHello
	length := binary.BigEndian.Uint16(packet[3:5]) + 5
	serverhello := parseTLSHandshake(packet[5:length], "1.3").(ServerHello)
	serverkeyshare := serverhello.TLSExtensions[1].Value.(map[string]interface{})["KeyExchange"]

	// Serverhelloをmessageに入れておく
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, packet[5:length]...)
	tlsinfo.State = ContentTypeHandShake

	var msinfo MasterSecretInfo
	msinfo.PreMasterSecret = serverkeyshare.([]byte)
	msinfo.ServerRandom = serverhello.Random
	msinfo.ClientRandom = noRandomByte(32)

	fmt.Printf("server key share is %x\n", serverkeyshare.([]byte))
	fmt.Printf("privateKey is %x\n", tlsinfo.ECDHEKeys.privateKey)
	sharedkey, _ := curve25519.X25519(tlsinfo.ECDHEKeys.privateKey, serverkeyshare.([]byte))
	fmt.Printf("sharedkey is %x\n", sharedkey)

	tlsinfo.KeyBlockTLS13 = keyscheduleToMasterSecret(sharedkey, tlsinfo.Handshakemessages)

	copy(packet, packet[length:])

	// read ChangeCipherSpec
	changecipherspec := packet[0:6]
	fmt.Printf("read ChangeCipherSpec is %x, It's OK!\n", changecipherspec)
	copy(packet, packet[6:])

	hanshake := bytes.Split(packet, []byte{0x17, 0x03, 0x03})
	for _, v := range hanshake {
		if len(v) != 0 /*&& (len(v)-2) == int(binary.BigEndian.Uint16(v[0:2]))*/ {
			v = append([]byte{0x17, 0x03, 0x03}, v...)
			length := binary.BigEndian.Uint16(v[3:5]) + 5

			plaintext := decryptChacha20(v[0:length], tlsinfo)
			tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, plaintext[0:len(plaintext)-1]...)
			parseTLSHandshake(plaintext[0:len(plaintext)-1], "1.3")

			tlsinfo.ServerHandshakeSeq++
			// Finishedまで来たら終了
			if bytes.Equal(plaintext[0:1], []byte{HandshakeTypeFinished}) {
				break
			}
			//fmt.Printf("app data from server : %s\n", string(serverappdata))
		}
	}

	// App用のキーを作る
	tlsinfo = keyscheduleToAppTraffic(tlsinfo)
	fmt.Printf("tlsinfo.KeyBlockTLS13 is %+v\n", tlsinfo.KeyBlockTLS13)

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
	appData := []byte("hello\n")
	appData = append(appData, ContentTypeApplicationData)
	encAppData := encryptChacha20(appData, tlsinfo)
	fmt.Printf("encAppData %x\n", encAppData)

	syscall.Write(sock, encAppData)
	tlsinfo.ClientAppSeq++

	fmt.Println("send Application data")
	for {
		recvBuf := make([]byte, 2000)
		n, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		fmt.Printf("recv App Data is %x\n", recvBuf[0:n])
		length := binary.BigEndian.Uint16(recvBuf[3:5])
		plaintext := decryptChacha20(recvBuf[0:length+5], tlsinfo)
		fmt.Printf("\nplaintext is %s\n", string(plaintext[0:len(plaintext)-1]))
		break
	}

	closeNotify := encryptChacha20(strtoByte("010015"), tlsinfo)
	// Close notifyで接続終了する
	syscall.Write(sock, closeNotify)
	fmt.Println("send close notify")
	for {
		recvBuf := make([]byte, 2000)
		n, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		fmt.Printf("%x\n", recvBuf[0:n])
		break
	}

}
