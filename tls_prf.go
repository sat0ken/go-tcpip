package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
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

func createVerifyData(premasterBytes MasterSecret, serverProtocolBytes []byte) ([]byte, KeyBlock) {
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

	// これまでの全てのhandshake protocolでハッシュを計算する
	hasher := sha256.New()
	hasher.Write(serverProtocolBytes)
	messages := hasher.Sum(nil)

	result := prf(master, []byte(`client finished`), messages, 12)
	fmt.Printf("verify_data : %x\n", result)

	return result, keyblock
}

func createFinishTest() {

	var handshake_message []byte
	handshake_message = append(handshake_message, clienthello_byte...)
	handshake_message = append(handshake_message, serverhello_byte...)
	handshake_message = append(handshake_message, server_certificate_byte...)
	handshake_message = append(handshake_message, serverhellodone_byte...)
	handshake_message = append(handshake_message, clientkeyexchange_byte...)

	var premasterByte []byte
	premasterByte = append(premasterByte, TLS1_2...)
	premasterByte = append(premasterByte, noRandomByte(46)...)

	master := MasterSecret{
		PreMasterSecret: premasterByte,
		ServerRandom:    noRandomByte(32),
		ClientRandom:    noRandomByte(32),
	}

	// 12byteのverify_dataを作成
	verifyData, keyblock := createVerifyData(master, handshake_message)
	// finished messageを作成する、先頭にヘッダを入れてからverify_dataを入れる
	// 作成された16byteがplaintextとなり暗号化する
	finMessage := []byte{HandshakeTypeFinished}
	finMessage = append(finMessage, uintTo3byte(uint32(len(verifyData)))...)
	finMessage = append(finMessage, verifyData...)
	fmt.Printf("finMessage : %x\n", finMessage)

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

func decryptPremaster() {
	certfile, err := tls.LoadX509KeyPair("./debug/my-tls.pem", "./debug/my-tls-key.pem")
	if err != nil {
		log.Fatal(err)
	}

	//premaster, _ := hex.DecodeString("7d4e98e480ec763ba78b36413c0c13686297aad706653f5d2582a96a5006b3fe0e1d00f9f833f39a9d5459567587fcc7f00aad553f0f2ff5aca7efd18d2ef484cac000bdf8d77b80935b1c7053cc832c6d4dcbb51c597d19c0213abb97c06cec27bcd67512f280e1211f80be4056590a11679baeae64f71af8230c34ce7562b16fcdad1d4abfc9be0ef4d10e02b9ebcfda862b99d23f407ca62d2055d9df107434a0046c4915afca067c1a8be40a8ee6ab492a78f11e805b8facaf1ad10ddaf4734b0b5453252e5c231f946682b333d3a0e31128aa6cfc38c97fb6b0eb0fed04c62b32c4f392e8e5a7faa47c0e3c151f5014fea0b34a18fc08095b6afab1519a")
	premaster, _ := hex.DecodeString("8c444026ba3c7d7c3b13c6bbc272a06566b5ab61b7fd3a1d98ffe6f034838c441c6a763112be50be451042e1bdf508fecfc4d30f7b36f0a2a357221ccbb7ebad06b10ebb9b7637f0466707a1323bcfe14a3d2f3249b8ac634db17e46254a1f0fda304ed6317b008ba2c0073c4fa904ace5bbf70b9d8298b5a59b21b0d83f101e7d967668242ddf039a2bfcf0a1129d196aea517d9566fd4d7b57ceb494b8b2b62a04c0b4b56615826c7d6046c85644b5d2c87cc4dff454ce12b8f8973457ee40ff3ec33474f61d8a6116867d13ddd37b70704c35c415d69555cb4aaf1ec4142837d7d9db1c3e6494eee282500ebe907bae32b4bd81eda7cf5cb7bd35d94a2270")

	secret, err := rsa.DecryptPKCS1v15(rand.Reader, certfile.PrivateKey.(*rsa.PrivateKey), premaster)
	if err != nil {
		log.Fatalf("create premaster secret err : %v\n", err)
	}
	fmt.Printf("%x\n", secret)
}
