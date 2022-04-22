package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/k0kubun/pp/v3"
	"log"
	"os"
	"syscall"
	"time"
)

var clientHellostr = "01000096030300000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000002009c0100004b000500050100000000000a000a0008001d001700180019000b00020100000d001a0018080404030807080508060401050106010503060302010203ff0100010000120000002b0003020303"

var serverHellostr = "020000330303000000000000000000000000000000000000000000000000000000000000000000009c00000bff01000100000b00020100"

var serverCertificatestr = "0b00042100041e00041b308204173082027fa003020102020f059ac2235f09f0f8066c1544ed1a6e300d06092a864886f70d01010b0500305b311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131183016060355040b0c0f7361746f6b656e407361746f6b656e311f301d06035504030c166d6b63657274207361746f6b656e407361746f6b656e301e170d3232303430323032343930385a170d3234303730323032343930385a304331273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531183016060355040b0c0f7361746f6b656e407361746f6b656e30820122300d06092a864886f70d01010105000382010f003082010a0282010100c708440e307a7e8c40d686be0a258b3bd264ec025cfa651e16bcf22cd11bc44fb9bb5e29e361bf0612727338625783200297f3f5e7bc83abff25f4b2a3783f8ed6bfdff95b1d50490f990125e7a49cfac35de22eb69a1c438184780c71d880805106d9bdcbca5b53183615d9b450123517bf9dfa4e907c2e23abff604abbf97ec33df0154f7a0c6c0eaef7740bc14f810f47db904804b92a7db37f1bff460b486f9f8bc79f72e099fb0757b0e4472f28019688c5a47590ff1ec077f7754227104cfaa9674074c4c2f9458c7d6745609ad5db221a473edb3ed9032713228a278f3d0b81ec6585b9f3b7787889cf3dd11194cf7cb409bea503582c7b285490aa570203010001a370306e300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301f0603551d2304183016801404d98d95143b1c115acc6ca986000253e9c9feb430260603551d11041f301d820a6d792d746c732e636f6d82096c6f63616c686f737487047f000001300d06092a864886f70d01010b0500038201810027d1655962c4f648a79735dfc31461db16b92f2a849d37886e353ee67a94d4d0f85b8c20e2207180d37af551a0a040cac73e5d7cf474b78e6d819afa543c334b2a949f3ef5f45f33e8c07f0e43e4d5f94f11c33d726d32458b87c82bbba12fa1f97aebdddcf5046c450fcef30e08e7bc371d300a0c48f91fe4b1b51de002481acdb15532596974983be65e4f1299cd2a43930c7de9d3c4dcb9f6c94f4f5047487694d4de4e6c08d3a737c3b40a943710c385264bb3b3a40aae1f66d4b54a458a6d5f4691b48112aae3ef6bbb96c002c4d4e8598319baf0fc1b3bdc895e1559f2b5f2748c61998ed182bb7ed43ad4cfd17b44953e571cfc2ccaf632cd1569d43d3fb7262da4c023b0e10417edafeb03d0df59e797cfa5ec58dc9ccc10d868f39dee0a6af29736b7f1d1ba5506fcb42ca99397a5f4bad7fa34e5470d1606fa99f65a56ca23afa9ae6d712d8030885bc69ed5fcff463aec982585965ca7b3573540fc3b4685cb3e4c287c1632d4aa9860b6e06a963151a7285c46bd8988df1943ee"

var serverCertRequeststr = "0d00001f02014000180804040308070805080604010501060105030603020102030000"

var serveHelloDonestr = "0e000000"

var clientCertficatestr = "0b00042c000429000426308204223082028aa00302010202107b12966cb053c48e9006e42c024e579f300d06092a864886f70d01010b0500305b311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131183016060355040b0c0f7361746f6b656e407361746f6b656e311f301d06035504030c166d6b63657274207361746f6b656e407361746f6b656e301e170d3232303431393132323633345a170d3234303731393132323633345a304331273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531183016060355040b0c0f7361746f6b656e407361746f6b656e30820122300d06092a864886f70d01010105000382010f003082010a0282010100d2d9152b796698d15e80bc8365431152b847c1dde6b028a5d8997904ce2d07091e8a93360853d42c3a68696420784f9e99bc48e74ac0a9c40bc05be71b25a03424e6e0d4facd6e1d32f4019d878fb0aa320bfc08beea60ecc97845b88d0c0c19928974cf725236878a97c62f2d702ef3bd33f7e70e7c81ab0658eb63edf897c62ab3c1460e612678b903737af197a16c7932557a8cadcdec564b4352b619aecfe10dc6d5764b94f4a0ce092c7261fed60bcf27c06afbb25727ac289a2ccaff9d7e7b3509141a6e960b7d982c72ef047bd932bc8e1c9f4d46b1a9813f2f049479aefa5b32f6180af2be804dd64653de08cca66efe49c2815706a0396d0badebbb0203010001a37a3078300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030206082b06010505070301301f0603551d2304183016801404d98d95143b1c115acc6ca986000253e9c9feb430260603551d11041f301d820a6d792d746c732e636f6d82096c6f63616c686f737487047f000001300d06092a864886f70d01010b050003820181001f24ac641b5203d540b8216f5371d447df58071a6a7b1e86b3cb396a8deec93f9d0e91f9d22291dcee2a5559a1fa6cd0ebaed36067a5b66c257a343c4e29152405fe68e66362b0f59dac7a49382ae257ccd1063b497d6af4716f4d06c0a14ef9ff144a3c196a55902d79ca7d053b1fd01ae3dd2789f63a63f5055464f9b36ff716b6af3d9804871293219bdf94c72597a2d970f74aec9fb84c35d35bb317a74e7938220566b738761e18488d27f0bd4883a43397d723c40a00b291c85f21d138684ff6acf2b04068850d2f5b3f53315c4866e1627f9aa9dbb0caa140feef88a441bb9074146343a3ad1561ee4ac2c19c6635188a2cb3453e64c8b86599cf9a9081c887b6e9bb2eb7e7548191beafbd13bad5e6ab0d582d566624b7ad08dc88496a88c36d587ab8062a6d4a4237914ec0d74ff97a509faadab912634b2692ba7bc37f54aaa87605077177134509b088c0d39b2a2cf9643a4de8e4d3e4cfad1c4a1d58eb0d3908e44205cf503f7a0f0acd7949d6c5968ad19df97517220a7299f5"

var clientKeyExchagestr = "1000010201007d4e98e480ec763ba78b36413c0c13686297aad706653f5d2582a96a5006b3fe0e1d00f9f833f39a9d5459567587fcc7f00aad553f0f2ff5aca7efd18d2ef484cac000bdf8d77b80935b1c7053cc832c6d4dcbb51c597d19c0213abb97c06cec27bcd67512f280e1211f80be4056590a11679baeae64f71af8230c34ce7562b16fcdad1d4abfc9be0ef4d10e02b9ebcfda862b99d23f407ca62d2055d9df107434a0046c4915afca067c1a8be40a8ee6ab492a78f11e805b8facaf1ad10ddaf4734b0b5453252e5c231f946682b333d3a0e31128aa6cfc38c97fb6b0eb0fed04c62b32c4f392e8e5a7faa47c0e3c151f5014fea0b34a18fc08095b6afab1519a"

var certVerifystr = "0f00010408040100a11b44a06d3453d85a2a3185830773de8ec150ad8316b42fcca232946a103783784a3996a30da47041cb73991396fd5a4e6ac565c2298819b58cfaf3037d89dc6bea9ef59313d898ca696291f276cf7beb2ee673890c595d4ad93937f5511737c36671e78bcd3b7ac397d7c1b340957b395fac000b2e6b0e0a3ecd27b0e34924b2445bc4bb0ff6234c64ba2b0a94b48191d87c773a19ba223e14f5a02eeb292997b0cf0dbf0df0878e9f336766fa69ba43ca16bea28d93b6456bc56ecea96463b88e090b59a00d37a861ab21c9d20d6f1358818923c2bcf6dc2ac2fa28360676a657e43f715d1c86af286d0302d195e89761d4617a9d1044e31d7646f08cd6c4"

var clientFinishstr = "1400000cf7c787cbcc6d24426f30b075"

var tlspacketstr = "1603030037020000330303000000000000000000000000000000000000000000000000000000000000000000c02f00000bff01000100000b0002010016030304250b00042100041e00041b308204173082027fa003020102020f059ac2235f09f0f8066c1544ed1a6e300d06092a864886f70d01010b0500305b311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131183016060355040b0c0f7361746f6b656e407361746f6b656e311f301d06035504030c166d6b63657274207361746f6b656e407361746f6b656e301e170d3232303430323032343930385a170d3234303730323032343930385a304331273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531183016060355040b0c0f7361746f6b656e407361746f6b656e30820122300d06092a864886f70d01010105000382010f003082010a0282010100c708440e307a7e8c40d686be0a258b3bd264ec025cfa651e16bcf22cd11bc44fb9bb5e29e361bf0612727338625783200297f3f5e7bc83abff25f4b2a3783f8ed6bfdff95b1d50490f990125e7a49cfac35de22eb69a1c438184780c71d880805106d9bdcbca5b53183615d9b450123517bf9dfa4e907c2e23abff604abbf97ec33df0154f7a0c6c0eaef7740bc14f810f47db904804b92a7db37f1bff460b486f9f8bc79f72e099fb0757b0e4472f28019688c5a47590ff1ec077f7754227104cfaa9674074c4c2f9458c7d6745609ad5db221a473edb3ed9032713228a278f3d0b81ec6585b9f3b7787889cf3dd11194cf7cb409bea503582c7b285490aa570203010001a370306e300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301f0603551d2304183016801404d98d95143b1c115acc6ca986000253e9c9feb430260603551d11041f301d820a6d792d746c732e636f6d82096c6f63616c686f737487047f000001300d06092a864886f70d01010b0500038201810027d1655962c4f648a79735dfc31461db16b92f2a849d37886e353ee67a94d4d0f85b8c20e2207180d37af551a0a040cac73e5d7cf474b78e6d819afa543c334b2a949f3ef5f45f33e8c07f0e43e4d5f94f11c33d726d32458b87c82bbba12fa1f97aebdddcf5046c450fcef30e08e7bc371d300a0c48f91fe4b1b51de002481acdb15532596974983be65e4f1299cd2a43930c7de9d3c4dcb9f6c94f4f5047487694d4de4e6c08d3a737c3b40a943710c385264bb3b3a40aae1f66d4b54a458a6d5f4691b48112aae3ef6bbb96c002c4d4e8598319baf0fc1b3bdc895e1559f2b5f2748c61998ed182bb7ed43ad4cfd17b44953e571cfc2ccaf632cd1569d43d3fb7262da4c023b0e10417edafeb03d0df59e797cfa5ec58dc9ccc10d868f39dee0a6af29736b7f1d1ba5506fcb42ca99397a5f4bad7fa34e5470d1606fa99f65a56ca23afa9ae6d712d8030885bc69ed5fcff463aec982585965ca7b3573540fc3b4685cb3e4c287c1632d4aa9860b6e06a963151a7285c46bd8988df1943ee160303012c0c00012803001d202fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74080401008f32a49217b0819836f2566a6aab44264859c0f4c26f7d815e96f29d4024992393f462f5658bd8c56ab5fea2fe1eb98320ee47afe8a597fac6c07b9f3b0e88ab3879513219417b80417ab097b7fec641a8acd74735447353380ea121edec5d64652da94981d42a1b0b1cde10ca849a2956bdda122612e11af554d5bb970c7d82cf31650392c7097722756b155780bbf9af22e27320eb47a0d9faeed4b43894ed8a9d8e550118add22db548de03ebf878881ab0b3fe035dc5f51bfad8033114d7bd33f10dae2356b28c8079804d35ebfb2280b478369ba2f31df28ac1cfac082d4fb14fb457fd5e29e32d540cb5c4cdf1e7706083c1ef4476ba9d31a392a36bd616030300040e000000"

func __() {
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

	//buf := strtoByte("16030300510200004d0303312c10799a53725901e6eef223378bbdd1bbdbcdab5d3856444f574e4752440120eea9d190349cd40a738e06582019d47037ad53e4d1bc57006b981fa4da7ad1d4009c000005ff0100010016030304250b00042100041e00041b308204173082027fa003020102020f059ac2235f09f0f8066c1544ed1a6e300d06092a864886f70d01010b0500305b311e301c060355040a13156d6b6365727420646576656c6f706d656e7420434131183016060355040b0c0f7361746f6b656e407361746f6b656e311f301d06035504030c166d6b63657274207361746f6b656e407361746f6b656e301e170d3232303430323032343930385a170d3234303730323032343930385a304331273025060355040a131e6d6b6365727420646576656c6f706d656e7420636572746966696361746531183016060355040b0c0f7361746f6b656e407361746f6b656e30820122300d06092a864886f70d01010105000382010f003082010a0282010100c708440e307a7e8c40d686be0a258b3bd264ec025cfa651e16bcf22cd11bc44fb9bb5e29e361bf0612727338625783200297f3f5e7bc83abff25f4b2a3783f8ed6bfdff95b1d50490f990125e7a49cfac35de22eb69a1c438184780c71d880805106d9bdcbca5b53183615d9b450123517bf9dfa4e907c2e23abff604abbf97ec33df0154f7a0c6c0eaef7740bc14f810f47db904804b92a7db37f1bff460b486f9f8bc79f72e099fb0757b0e4472f28019688c5a47590ff1ec077f7754227104cfaa9674074c4c2f9458c7d6745609ad5db221a473edb3ed9032713228a278f3d0b81ec6585b9f3b7787889cf3dd11194cf7cb409bea503582c7b285490aa570203010001a370306e300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301f0603551d2304183016801404d98d95143b1c115acc6ca986000253e9c9feb430260603551d11041f301d820a6d792d746c732e636f6d82096c6f63616c686f737487047f000001300d06092a864886f70d01010b0500038201810027d1655962c4f648a79735dfc31461db16b92f2a849d37886e353ee67a94d4d0f85b8c20e2207180d37af551a0a040cac73e5d7cf474b78e6d819afa543c334b2a949f3ef5f45f33e8c07f0e43e4d5f94f11c33d726d32458b87c82bbba12fa1f97aebdddcf5046c450fcef30e08e7bc371d300a0c48f91fe4b1b51de002481acdb15532596974983be65e4f1299cd2a43930c7de9d3c4dcb9f6c94f4f5047487694d4de4e6c08d3a737c3b40a943710c385264bb3b3a40aae1f66d4b54a458a6d5f4691b48112aae3ef6bbb96c002c4d4e8598319baf0fc1b3bdc895e1559f2b5f2748c61998ed182bb7ed43ad4cfd17b44953e571cfc2ccaf632cd1569d43d3fb7262da4c023b0e10417edafeb03d0df59e797cfa5ec58dc9ccc10d868f39dee0a6af29736b7f1d1ba5506fcb42ca99397a5f4bad7fa34e5470d1606fa99f65a56ca23afa9ae6d712d8030885bc69ed5fcff463aec982585965ca7b3573540fc3b4685cb3e4c287c1632d4aa9860b6e06a963151a7285c46bd8988df1943ee16030300040e000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	//b := bytes.Split(buf, []byte{0x16, 0x03, 0x03})
	//
	//copy(b, b[1:len(b)-1])
	//
	//for _, v := range b {
	//	fmt.Println(v[2])
	//	fmt.Printf("%x\n", v)
	//}
	tlsprotcols, _ := parseTLSPacket(strtoByte(tlspacketstr))
	for _, v := range tlsprotcols {
		switch proto := v.HandshakeProtocol.(type) {
		case ServerKeyExchange:
			// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
			// https://cs.opensource.google/go/go/+/master:src/crypto/tls/common.go;drc=2580d0e08d5e9f979b943758d3c49877fb2324cb;l=118
			// 楕円曲線Curve25519だけサポートする
			if proto.ECDiffieHellmanServerParams.NamedCurve[1] == CurveIDx25519 {
				b := genrateECDHESharedKey(proto.ECDiffieHellmanServerParams.Pubkey)
				var clientKeyExchange ClientKeyExchange
				var clientKeyExchangeBytes []byte

				clientKeyExchangeBytes = clientKeyExchange.NewClientKeyECDHAExchange(b.publicKey)
				fmt.Printf("%x\n", clientKeyExchangeBytes)
			}
		}

	}

}

func _() {
	b, _ := os.ReadFile("debug/client-key.pem")

	block, _ := pem.Decode(b)
	fmt.Println(block.Type)

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("parse private key is err : %v\n", err)
	}

	privatekey := key.(*rsa.PrivateKey)

	all_message := clientHellostr
	all_message += serverHellostr + serverCertificatestr + serverCertRequeststr + serveHelloDonestr
	all_message += clientCertficatestr + clientKeyExchagestr

	hasher := sha256.New()
	hasher.Write(strtoByte(all_message))
	tokenhash := hasher.Sum(nil)

	sig, err := rsa.SignPKCS1v15(zeroSource{}, privatekey, crypto.SHA256, tokenhash)
	fmt.Printf("signature : %x\n", sig)

}

func _() {
	certs, err := tls.LoadX509KeyPair("debug/client.pem", "debug/client-key.pem")
	if err != nil {
		log.Fatal(err)
	}

	//all_message := clientHellostr
	//all_message += serverHellostr + serverCertificatestr + serverCertRequeststr + serveHelloDonestr
	//all_message += clientCertficatestr + clientKeyExchagestr
	//
	//hasher := sha256.New()
	//hasher.Write(strtoByte(all_message))
	//tokenhash := hasher.Sum(nil)

	//fmt.Printf("hash is %x\n", tokenhash)
	//
	//rsaPrivatekey := certs.PrivateKey.(*rsa.PrivateKey)
	//rsaPrivatekey2 := certs.PrivateKey.(crypto.Signer)
	//
	//sig, _ := rsaPrivatekey2.Sign(zeroSource{}, tokenhash, crypto.SignerOpts(crypto.SHA256))
	//
	//signature, err := rsa.SignPKCS1v15(zeroSource{}, rsaPrivatekey, crypto.SHA256, tokenhash)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//
	//fmt.Printf("signature : %x\n", signature)
	//fmt.Printf("signature2 : %x\n", sig)

	tokenhash := strtoByte("beddcd1048b34aa0f6331ae349825d65a694cb73704894c846047401fcac938e")
	signature := strtoByte("2cd14567fc97206a87d7958aeaa2c57d6ac7c2a16da3a135e9dde8bc87c45e82edcdce5aee87c5f61bba5231e5a3245fa13ed37230794dfa6707adbd1976f07fdc66d7374c70eff955f0096144fb7cb7c11e7e0a4c457f2f450809ed1d977c63dc8913729f72b15c12b4299b18e1dc30992b993d01e60ecfe9e6500ddebfbb6525bd912b0fcd4d1b9eda1ca2dee8063e2edf8a8f1c51e21e12ef2a9b642af9d5d178b0e652f331d2b5a2d85fc3e09436c48476b59e7118f6488bc2233255c248c82120d44f5aff0278d213be97bdb209221224af7c06f9cbf083d456ebcc99a03279c8472802e6a313bfc7b3176440dc6cd2382011519752376532c9b2ef551b")

	// サーバ側でやること
	cert, err := x509.ParseCertificate(certs.Certificate[0])
	if err != nil {
		log.Fatalf("parse certificate err : %v\n", err)
	}
	rsaPublickey := cert.PublicKey.(*rsa.PublicKey)
	fmt.Println(rsaPublickey.N)

	signOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	if err := rsa.VerifyPSS(rsaPublickey, crypto.SHA256, tokenhash, signature, signOpts); err != nil {
		log.Fatal(err)
	}

	log.Println("success")
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
