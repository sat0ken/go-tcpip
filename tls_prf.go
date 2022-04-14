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

func createVerifyData(premasterBytes MasterSecret, labels, handhake_messages []byte) ([]byte, KeyBlock, []byte) {
	var random []byte
	//random = append(random, premasterBytes.ClientRandom...)
	// client randomeはいったん All zero
	random = append(random, noRandomByte(32)...)
	random = append(random, premasterBytes.ServerRandom...)

	// master secretを作成する
	master := prf(premasterBytes.PreMasterSecret, MasterSecretLable, random, 48)

	keyblockbyte := prf(master, KeyLable, random, 40)
	keyblock := KeyBlock{
		ClientWriteKey: keyblockbyte[0:16],
		ServerWriteKey: keyblockbyte[16:32],
		ClientWriteIV:  keyblockbyte[32:36],
		ServerWriteIV:  keyblockbyte[36:40],
	}
	fmt.Printf("ServerWriteKey : %s\n", printByteArr(keyblock.ServerWriteKey))
	fmt.Printf("ServerWriteIV : %s\n", printByteArr(keyblock.ServerWriteIV))

	// これまでの全てのhandshake protocolでハッシュを計算する
	hasher := sha256.New()
	hasher.Write(handhake_messages)
	messages := hasher.Sum(nil)

	result := prf(master, labels, messages, 12)
	//fmt.Printf("verify_data : %x\n", result)

	return result, keyblock, master
}

func createServerVerifyData(master, serverFinMessage []byte) []byte {

	// これまでの全てのhandshake protocolでハッシュを計算する
	hasher := sha256.New()
	hasher.Write(serverFinMessage)
	messages := hasher.Sum(nil)

	result := prf(master, ServerFinished, messages, 12)

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

	master := MasterSecret{
		PreMasterSecret: premasterByte,
		ServerRandom:    noRandomByte(32),
		ClientRandom:    noRandomByte(32),
	}

	// 12byteのverify_dataを作成
	verifyData, keyblock, masterByte := createVerifyData(master, CLientFinished, handshake_message)
	fmt.Printf("client verifyData : %x\n", verifyData)

	// finished messageを作成する、先頭にレコードヘッダを入れてからverify_dataを入れる
	// 作成された16byteがplaintextとなり暗号化する
	finMessage := []byte{HandshakeTypeFinished}
	finMessage = append(finMessage, uintTo3byte(uint32(len(verifyData)))...)
	finMessage = append(finMessage, verifyData...)
	fmt.Printf("finMessage : %x\n", finMessage)

	handshake_message = append(handshake_message, finMessage...)
	//serververifyData, _ := createVerifyData(master, ServerFinished, handshake_message)
	fmt.Printf("server verifyData : %x\n", createServerVerifyData(masterByte, handshake_message))

	rheader := TLSRecordHeader{
		ContentType:     []byte{ContentTypeHandShake},
		ProtocolVersion: TLS1_2,
		Length:          uintTo2byte(uint16(len(finMessage))),
	}

	encryptMessage(rheader, keyblock.ClientWriteIV, finMessage, keyblock.ClientWriteKey)
}

func encryptMessage(header TLSRecordHeader, prenonce, plaintext, clientkey []byte) []byte {
	//record, _ := hex.DecodeString("16030300100000000000000000")
	record_seq := toByteArr(header)
	record_seq = append(record_seq, getNonce(0)...)

	//nonce, _ := hex.DecodeString("6f91b6850000000000000000")
	nonce := prenonce
	nonce = append(nonce, getNonce(0)...)

	//plaintext2, _ := hex.DecodeString("1400000cfce82f0b05fe58f0279716c3")
	//add, _ := hex.DecodeString("00000000000000001603030010")
	add := getNonce(0)
	add = append(add, toByteArr(header)...)

	//key, _ := hex.DecodeString("5fa182b333543f7cf6dcf0eceebe9393")
	block, _ := aes.NewCipher(clientkey)
	aesgcm, _ := cipher.NewGCM(block)

	encryptedMessage := aesgcm.Seal(record_seq, nonce, plaintext, add)
	updatelength := uintTo2byte(uint16(len(encryptedMessage) - 5))
	encryptedMessage[3] = updatelength[0]
	encryptedMessage[4] = updatelength[1]

	fmt.Printf("encrypted data is : %x\n", encryptedMessage)

	return encryptedMessage
}

func decryptServerFinMessage(finMessage []byte, keyblock KeyBlock) []byte {

	//header := TLSRecordHeader{
	//	ContentType:     finMessage[0:1],
	//	ProtocolVersion: finMessage[1:3],
	//	Length:          finMessage[3:5],
	//}

	header := readByteNum(finMessage, 0, 5)
	ciphertextLength := binary.BigEndian.Uint16(header[3:]) - 8

	seq_nonce := readByteNum(finMessage, 5, 8)
	ciphertext := readByteNum(finMessage, 13, int64(ciphertextLength))

	//strtoByte("427ee17499822aea9bffa09c420f78630268de7926f162002809b8ad1f5096e3")

	//header := []byte{ContentTypeHandShake}
	//header := append(header, TLS1_2...)

	//record := strtoByte("16030300100000000000000000")
	//serverkey := strtoByte("475f58d5ca2aa6b36add62077ea4a340")
	//nonce := strtoByte("0bcd1746")
	serverkey := keyblock.ServerWriteKey
	nonce := keyblock.ServerWriteIV
	nonce = append(nonce, seq_nonce...)

	block, _ := aes.NewCipher(serverkey)
	aesgcm, _ := cipher.NewGCM(block)

	var add []byte
	add = readByteNum(finMessage, 5, 8)
	add = append(add, ContentTypeHandShake)
	add = append(add, TLS1_2...)
	plainLength := len(ciphertext) - aesgcm.Overhead()
	add = append(add, uintTo2byte(uint16(plainLength))...)

	fmt.Printf("nonce is : %x, ciphertext is %x, add is %x\n", nonce, ciphertext, add)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, add)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("decrypt is %x\n", plaintext)

	return plaintext

}

func decryptFinTest() {

	ciphertext := strtoByte("427ee17499822aea9bffa09c420f78630268de7926f162002809b8ad1f5096e3")

	//header := []byte{ContentTypeHandShake}
	//header := append(header, TLS1_2...)

	//record := strtoByte("16030300100000000000000000")
	seq_nonce := getNonce(0)

	serverkey := strtoByte("475f58d5ca2aa6b36add62077ea4a340")
	nonce := strtoByte("0bcd1746")
	nonce = append(nonce, seq_nonce...)

	block, _ := aes.NewCipher(serverkey)
	aesgcm, _ := cipher.NewGCM(block)

	add := seq_nonce
	plainLength := len(ciphertext) - aesgcm.Overhead()
	add = append(add, []byte{0x16, 0x03, 0x03}...)
	add = append(add, uintTo2byte(uint16(plainLength))...)

	///plainLength := uintTo2byte(uint16(len(ciphertext) - aesgcm.Overhead()))
	fmt.Printf("nonce is : %x, ciphertext is %x, add is %x\n", nonce, ciphertext, add)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, add)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("decrypt is %x\n", plaintext)

}

func decryptPremaster() {
	certfile, err := tls.LoadX509KeyPair("./debug/my-tls.pem", "./debug/my-tls-key.pem")
	if err != nil {
		log.Fatal(err)
	}

	//premaster, _ := hex.DecodeString("7d4e98e480ec763ba78b36413c0c13686297aad706653f5d2582a96a5006b3fe0e1d00f9f833f39a9d5459567587fcc7f00aad553f0f2ff5aca7efd18d2ef484cac000bdf8d77b80935b1c7053cc832c6d4dcbb51c597d19c0213abb97c06cec27bcd67512f280e1211f80be4056590a11679baeae64f71af8230c34ce7562b16fcdad1d4abfc9be0ef4d10e02b9ebcfda862b99d23f407ca62d2055d9df107434a0046c4915afca067c1a8be40a8ee6ab492a78f11e805b8facaf1ad10ddaf4734b0b5453252e5c231f946682b333d3a0e31128aa6cfc38c97fb6b0eb0fed04c62b32c4f392e8e5a7faa47c0e3c151f5014fea0b34a18fc08095b6afab1519a")
	premaster, _ := hex.DecodeString("64df1148bdeaaff4fb1a241e1c3fad5e72de3052872517cebe5580e149f4a7dae6f376702aa390e34a7f6ebe4abdf4f6444bb398d1a77c9b9be79c229e0dcdb8a15b3b4f908c611c9dd1b283acedc6e66bb0b301416965866200c9d84c28f4d5d48e159f6a5e86b9acec5c9f324813fc8bf7f5c13e6c74661ae88cbc5b9689bf1002d1764cce9f60393738202b62134e04f543046a47b84ac7d420ca3653af2fc5cafde09daf9d4c84dbf0fb38421603c909750f359ce82d83e6be6776fbc118e69ec083c0a6b208538317e1eebb1e5582b3dedd75a85f71e8f1ab3118fefe92152f66cb092a5af07b5e580f86067713a644be03d87fa96230e0e9b502f7987c")

	secret, err := rsa.DecryptPKCS1v15(rand.Reader, certfile.PrivateKey.(*rsa.PrivateKey), premaster)
	if err != nil {
		log.Fatalf("create premaster secret err : %v\n", err)
	}
	fmt.Printf("%x\n", secret)
}
