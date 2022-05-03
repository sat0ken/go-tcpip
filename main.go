package main

import (
	"bytes"
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
	hello := "010000ba03030000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000213030100006f000500050100000000000a00040002001d000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000120000002b0003020304003300260024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74"
	hello += "0200007603030000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000130300002e002b0002030400330024001d00202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74"
	hello += "080000020000"
	hello += "0b0004240000042000041b308204173082027fa003020102020f059ac2235f09f0f8066c1544ed1a6e300d06092a864886f70d01010b0500305b311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131183016060355040b0c0f7361746f6b656e407361746f6b656e311f301d06035504030c166d6b63657274207361746f6b656e407361746f6b656e301e170d3232303430323032343930385a170d3234303730323032343930385a304331273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531183016060355040b0c0f7361746f6b656e407361746f6b656e30820122300d06092a864886f70d01010105000382010f003082010a0282010100c708440e307a7e8c40d686be0a258b3bd264ec025cfa651e16bcf22cd11bc44fb9bb5e29e361bf0612727338625783200297f3f5e7bc83abff25f4b2a3783f8ed6bfdff95b1d50490f990125e7a49cfac35de22eb69a1c438184780c71d880805106d9bdcbca5b53183615d9b450123517bf9dfa4e907c2e23abff604abbf97ec33df0154f7a0c6c0eaef7740bc14f810f47db904804b92a7db37f1bff460b486f9f8bc79f72e099fb0757b0e4472f28019688c5a47590ff1ec077f7754227104cfaa9674074c4c2f9458c7d6745609ad5db221a473edb3ed9032713228a278f3d0b81ec6585b9f3b7787889cf3dd11194cf7cb409bea503582c7b285490aa570203010001a370306e300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301f0603551d2304183016801404d98d95143b1c115acc6ca986000253e9c9feb430260603551d11041f301d820a6d792d746c732e636f6d82096c6f63616c686f737487047f000001300d06092a864886f70d01010b0500038201810027d1655962c4f648a79735dfc31461db16b92f2a849d37886e353ee67a94d4d0f85b8c20e2207180d37af551a0a040cac73e5d7cf474b78e6d819afa543c334b2a949f3ef5f45f33e8c07f0e43e4d5f94f11c33d726d32458b87c82bbba12fa1f97aebdddcf5046c450fcef30e08e7bc371d300a0c48f91fe4b1b51de002481acdb15532596974983be65e4f1299cd2a43930c7de9d3c4dcb9f6c94f4f5047487694d4de4e6c08d3a737c3b40a943710c385264bb3b3a40aae1f66d4b54a458a6d5f4691b48112aae3ef6bbb96c002c4d4e8598319baf0fc1b3bdc895e1559f2b5f2748c61998ed182bb7ed43ad4cfd17b44953e571cfc2ccaf632cd1569d43d3fb7262da4c023b0e10417edafeb03d0df59e797cfa5ec58dc9ccc10d868f39dee0a6af29736b7f1d1ba5506fcb42ca99397a5f4bad7fa34e5470d1606fa99f65a56ca23afa9ae6d712d8030885bc69ed5fcff463aec982585965ca7b3573540fc3b4685cb3e4c287c1632d4aa9860b6e06a963151a7285c46bd8988df1943ee0000"
	hello += "0f00010408040100c3bce6e5becc22190bc1c2a6d228cca3ea8dda8a6bd350526c540cd11423b942f7e0d33630c651f1a33c10301a84ce5844ac1b98b3373de2100998f993e6237697ee5bdde8a8278020efd6affd2040cc4bbbd1e4266f0a7592f2cde0c3409d72a9bef153f2c9cd23e088682bf9ccf238d07254be441a3855691019970ab001ea9c93948aa06c31318265811ec88d949b30172abdbef28e3361d7ad9791ba7c969c765f3e8190bb6fb30627bc48b616fd8063ab3f2484aa9f5004fd93d9a81f16ce2db4d3be2eff53a0744c6114367776807f078ca03847dc17c33a6fe65f24c25bb0094013e90cc5b8e07b928870c318f4983a31a79f2fb830e6f69c6af7c36c"

	hasher := sha256.New()
	hasher.Write(strtoByte(hello))

	fmt.Printf("%x\n", hasher.Sum(nil))
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
	tlsinfo.State = "Handshake"

	var msinfo MasterSecretInfo
	msinfo.PreMasterSecret = serverkeyshare.([]byte)
	msinfo.ServerRandom = serverhello.Random
	msinfo.ClientRandom = noRandomByte(32)

	fmt.Printf("server key share is %x\n", serverkeyshare.([]byte))
	fmt.Printf("privateKey is %x\n", tlsinfo.ECDHEKeys.privateKey)
	sharedkey, _ := curve25519.X25519(tlsinfo.ECDHEKeys.privateKey, serverkeyshare.([]byte))
	fmt.Printf("sharedkey is %x\n", sharedkey)

	tlsinfo.KeyBlockTLS13 = keyscheduleTLS13(sharedkey, tlsinfo.Handshakemessages)

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
			//fmt.Printf("%x\n", v[0:length])
			serverappdata := decryptChacha20(v[0:length], tlsinfo)
			tlsinfo.ClientSequenceNum++
			_ = serverappdata
			//fmt.Printf("app data from server : %s\n", string(serverappdata))
		}
	}

}
