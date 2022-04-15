package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
)

// HMAC およびその擬似乱数関数
// https://www.ipa.go.jp/security/rfc/RFC5246-05JA.html
// https://atmarkit.itmedia.co.jp/ait/articles/0101/16/news002_4.html
// https://www.slideshare.net/shigeki_ohtsu/security-camp2015-tls
// https://github.com/shigeki/SecCamp2015-TLS/blob/master/MyMasterSecret.js
// データ拡張関数, あるsecretを必要なサイズまで伸長させる
func phash(secret, seed []byte, prfLength int) []byte {
	result := make([]byte, prfLength)
	mac := hmac.New(sha256.New, secret)
	mac.Write(seed)

	// A(1)
	a := mac.Sum(nil)
	length := 0

	// 48byteになるまで計算する
	for length < len(result) {
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		b := mac.Sum(nil)
		copy(result[length:], b)
		length += len(b)

		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
	}
	return result
}

// https://www.ipa.go.jp/security/rfc/RFC5246-08JA.html#081
// ClientKeyExchangeのときに生成したpremaster secretと
// ClientHelloで送ったrandom, ServerHelloで受信したrandomをもとに48byteのmaster secretを生成する
func prf(secret, label, clientServerRandom []byte, prfLength int) []byte {
	var seed []byte
	seed = append(seed, label...)
	seed = append(seed, clientServerRandom...)
	return phash(secret, seed, prfLength)
}

func createVerifyData(premasterBytes MasterSecretInfo, labels, handhake_messages []byte) ([]byte, KeyBlock, []byte) {
	var random []byte
	// client randomeはいったん All zero
	random = append(random, premasterBytes.ClientRandom...)
	random = append(random, premasterBytes.ServerRandom...)

	// keyblockを作るときはServer→ClienRandomの順番
	// https://www.ipa.go.jp/security/rfc/RFC5246-06JA.html#063
	var keyrandom []byte
	keyrandom = append(keyrandom, premasterBytes.ServerRandom...)
	keyrandom = append(keyrandom, premasterBytes.ClientRandom...)

	// master secretを作成する
	master := prf(premasterBytes.PreMasterSecret, MasterSecretLable, random, 48)
	fmt.Printf("CLIENT_RANDOM %x %x\n", premasterBytes.ClientRandom, master)

	fmt.Printf("keyrandom : %x\n", keyrandom)
	keyblockbyte := prf(master, KeyLable, keyrandom, 40)
	keyblock := KeyBlock{
		ClientWriteKey: keyblockbyte[0:16],
		ServerWriteKey: keyblockbyte[16:32],
		ClientWriteIV:  keyblockbyte[32:36],
		ServerWriteIV:  keyblockbyte[36:40],
	}
	fmt.Printf("ClientWriteIV : %x\n", keyblock.ClientWriteIV)
	fmt.Printf("ServerWriteKey : %x\n", keyblock.ClientWriteKey)
	fmt.Printf("ServerWriteIV : %x\n", keyblock.ServerWriteIV)
	fmt.Printf("ServerWriteKey : %x\n", keyblock.ServerWriteKey)
	//fmt.Printf("ServerWriteKey : %x\n", keyblock.ServerWriteKey)

	// これまでの全てのhandshake protocolでハッシュを計算する
	hasher := sha256.New()
	hasher.Write(handhake_messages)
	messages := hasher.Sum(nil)

	// 12byteのverify_dataにする
	result := prf(master, labels, messages, 12)

	return result, keyblock, master
}

func createServerVerifyData(master, serverFinMessage []byte) []byte {

	// これまでの全てのhandshake protocolでハッシュを計算する
	hasher := sha256.New()
	hasher.Write(serverFinMessage)
	messages := hasher.Sum(nil)

	result := prf(master, ServerFinishedLabel, messages, 12)

	return result
}

func createFinishTest() {

	var handshake_message []byte
	handshake_message = append(handshake_message, strtoByte(clientHellostr)...)
	handshake_message = append(handshake_message, strtoByte(serverHellostr)...)
	handshake_message = append(handshake_message, strtoByte(serverCertificatestr)...)
	handshake_message = append(handshake_message, strtoByte(serveHelloDonestr)...)
	handshake_message = append(handshake_message, strtoByte(clientKeyExchagestr)...)

	var premasterByte []byte
	premasterByte = append(premasterByte, TLS1_2...)
	premasterByte = append(premasterByte, noRandomByte(46)...)

	serverrandom := strtoByte("e7084907d95b64c862825b77b73d38020d080eb924a3b7c0444f574e47524401")

	master := MasterSecretInfo{
		PreMasterSecret: premasterByte,
		ServerRandom:    serverrandom,
		ClientRandom:    noRandomByte(32),
	}

	// 12byteのverify_dataを作成
	verifyData, keyblock, _ := createVerifyData(master, CLientFinishedLabel, handshake_message)
	fmt.Printf("client verifyData : %x\n", verifyData)

	// finished messageを作成する、先頭にレコードヘッダを入れてからverify_dataを入れる
	// 作成された16byteがplaintextとなり暗号化する
	finMessage := []byte{HandshakeTypeFinished}
	finMessage = append(finMessage, uintTo3byte(uint32(len(verifyData)))...)
	finMessage = append(finMessage, verifyData...)
	fmt.Printf("finMessage : %x\n", finMessage)

	handshake_message = append(handshake_message, finMessage...)
	//serververifyData, _ := createVerifyData(master, ServerFinished, handshake_message)
	//fmt.Printf("server verifyData : %x\n", createServerVerifyData(masterByte, handshake_message))

	rheader := TLSRecordHeader{
		ContentType:     []byte{ContentTypeHandShake},
		ProtocolVersion: TLS1_2,
		Length:          uintTo2byte(uint16(len(finMessage))),
	}

	tlsinfo := TLSInfo{
		KeyBlock:          keyblock,
		ClientSequenceNum: 0,
	}

	encryptClientMessage(toByteArr(rheader), finMessage, tlsinfo)
}

func encryptClientMessage(header, plaintext []byte, tlsinfo TLSInfo) []byte {
	//record, _ := hex.DecodeString("16030300100000000000000000")
	//record_seq := toByteArr(header)
	record_seq := append(header, getNonce(tlsinfo.ClientSequenceNum)...)

	//nonce, _ := hex.DecodeString("6f91b6850000000000000000")
	nonce := tlsinfo.KeyBlock.ClientWriteIV
	nonce = append(nonce, getNonce(tlsinfo.ClientSequenceNum)...)

	//plaintext2, _ := hex.DecodeString("1400000cfce82f0b05fe58f0279716c3")
	//add, _ := hex.DecodeString("00000000000000001603030010")
	add := getNonce(tlsinfo.ClientSequenceNum)
	add = append(add, header...)

	//key, _ := hex.DecodeString("5fa182b333543f7cf6dcf0eceebe9393")
	block, _ := aes.NewCipher(tlsinfo.KeyBlock.ClientWriteKey)
	aesgcm, _ := cipher.NewGCM(block)

	fmt.Printf("record is %x, nonce is : %x, plaintext is %x, add is %x\n", record_seq, nonce, plaintext, add)
	encryptedMessage := aesgcm.Seal(record_seq, nonce, plaintext, add)
	updatelength := uintTo2byte(uint16(len(encryptedMessage) - 5))
	encryptedMessage[3] = updatelength[0]
	encryptedMessage[4] = updatelength[1]

	fmt.Printf("encrypted data is : %x\n", encryptedMessage)

	return encryptedMessage
}

func decryptServerMessage(finMessage []byte, tlsinfo TLSInfo, ctype int) []byte {

	header := readByteNum(finMessage, 0, 5)
	ciphertextLength := binary.BigEndian.Uint16(header[3:]) - 8

	seq_nonce := readByteNum(finMessage, 5, 8)
	ciphertext := readByteNum(finMessage, 13, int64(ciphertextLength))

	serverkey := tlsinfo.KeyBlock.ServerWriteKey
	nonce := tlsinfo.KeyBlock.ServerWriteIV
	nonce = append(nonce, seq_nonce...)

	block, _ := aes.NewCipher(serverkey)
	aesgcm, _ := cipher.NewGCM(block)

	var add []byte
	add = getNonce(tlsinfo.ClientSequenceNum)
	add = append(add, byte(ctype))
	add = append(add, TLS1_2...)
	plainLength := len(ciphertext) - aesgcm.Overhead()
	add = append(add, uintTo2byte(uint16(plainLength))...)

	//fmt.Printf("nonce is : %x, ciphertext is %x, add is %x\n", nonce, ciphertext, add)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, add)
	if err != nil {
		panic(err.Error())
	}

	return plaintext

}

func decryptFinTest() {
	serverrandom := strtoByte("94d1d67fb0fe4f841e88166a1572e7787307fb2c5cd56dcb444f574e47524401")
	clientrandom := noRandomByte(32)
	var random []byte
	// client randomeはいったん All zero
	random = append(random, clientrandom...)
	random = append(random, serverrandom...)

	// keyblockを作るときはServer→ClienRandomの順番
	// https://www.ipa.go.jp/security/rfc/RFC5246-06JA.html#063
	var keyrandom []byte
	keyrandom = append(keyrandom, serverrandom...)
	keyrandom = append(keyrandom, clientrandom...)

	var premasterByte []byte
	premasterByte = append(premasterByte, TLS1_2...)
	premasterByte = append(premasterByte, noRandomByte(46)...)

	// master secretを作成する
	master := prf(premasterByte, MasterSecretLable, random, 48)
	fmt.Printf("CLIENT_RANDOM %x %x\n", clientrandom, master)

	fmt.Printf("keyrandom : %x\n", keyrandom)
	keyblockbyte := prf(master, KeyLable, keyrandom, 40)
	keyblock := KeyBlock{
		ClientWriteKey: keyblockbyte[0:16],
		ServerWriteKey: keyblockbyte[16:32],
		ClientWriteIV:  keyblockbyte[32:36],
		ServerWriteIV:  keyblockbyte[36:40],
	}

	ciphertext := strtoByte("e40da4398ee3d35174abb36cd2c49160c19579d6aa08ccbf4684e09f93216bea")

	//header := []byte{ContentTypeHandShake}
	//header := append(header, TLS1_2...)

	//record := strtoByte("16030300100000000000000000")
	//seq_nonce := getNonce(1)
	nonce := keyblock.ServerWriteIV
	nonce = append(nonce, strtoByte("12355ff49c01a9b7")...)

	block, _ := aes.NewCipher(keyblock.ServerWriteKey)
	aesgcm, _ := cipher.NewGCM(block)

	add := getNonce(0)
	plainLength := len(ciphertext) - aesgcm.Overhead()
	add = append(add, []byte{0x16, 0x03, 0x03}...)
	add = append(add, uintTo2byte(uint16(plainLength))...)
	//add := strtoByte("00000000000000011703030006")

	///plainLength := uintTo2byte(uint16(len(ciphertext) - aesgcm.Overhead()))
	fmt.Printf("nonce is : %x, ciphertext is %x, add is %x\n", nonce, ciphertext, add)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, add)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("decrypt is %x\n", plaintext[4:])
	//fmt.Printf("AppData is %s\n", string(plaintext))
}

func decryptPremaster() {
	certfile, err := tls.LoadX509KeyPair("./debug/my-tls.pem", "./debug/my-tls-key.pem")
	if err != nil {
		log.Fatal(err)
	}

	//premaster, _ := hex.DecodeString("7d4e98e480ec763ba78b36413c0c13686297aad706653f5d2582a96a5006b3fe0e1d00f9f833f39a9d5459567587fcc7f00aad553f0f2ff5aca7efd18d2ef484cac000bdf8d77b80935b1c7053cc832c6d4dcbb51c597d19c0213abb97c06cec27bcd67512f280e1211f80be4056590a11679baeae64f71af8230c34ce7562b16fcdad1d4abfc9be0ef4d10e02b9ebcfda862b99d23f407ca62d2055d9df107434a0046c4915afca067c1a8be40a8ee6ab492a78f11e805b8facaf1ad10ddaf4734b0b5453252e5c231f946682b333d3a0e31128aa6cfc38c97fb6b0eb0fed04c62b32c4f392e8e5a7faa47c0e3c151f5014fea0b34a18fc08095b6afab1519a")
	premaster, _ := hex.DecodeString("7d4e98e480ec763ba78b36413c0c13686297aad706653f5d2582a96a5006b3fe0e1d00f9f833f39a9d5459567587fcc7f00aad553f0f2ff5aca7efd18d2ef484cac000bdf8d77b80935b1c7053cc832c6d4dcbb51c597d19c0213abb97c06cec27bcd67512f280e1211f80be4056590a11679baeae64f71af8230c34ce7562b16fcdad1d4abfc9be0ef4d10e02b9ebcfda862b99d23f407ca62d2055d9df107434a0046c4915afca067c1a8be40a8ee6ab492a78f11e805b8facaf1ad10ddaf4734b0b5453252e5c231f946682b333d3a0e31128aa6cfc38c97fb6b0eb0fed04c62b32c4f392e8e5a7faa47c0e3c151f5014fea0b34a18fc08095b6afab1519a")

	secret, err := rsa.DecryptPKCS1v15(rand.Reader, certfile.PrivateKey.(*rsa.PrivateKey), premaster)
	if err != nil {
		log.Fatalf("create premaster secret err : %v\n", err)
	}
	fmt.Printf("%x\n", secret)
}
