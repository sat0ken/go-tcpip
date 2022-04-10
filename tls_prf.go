package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
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
