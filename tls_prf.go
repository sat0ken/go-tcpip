package main

import (
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

func createFinishedMessage(premasterBytes MasterSecret, serverProtocolBytes []byte) []byte {
	var random []byte
	//random = append(random, premasterBytes.ClientRandom...)
	random = append(random, noRandomByte(32)...)
	random = append(random, premasterBytes.ServerRandom...)

	// master secretを作成する
	master := prf(premasterBytes.PreMasterSecret, MasterSecretLable, random, 48)

	fmt.Printf("master secret is %x\n", master)

	// これまでの全てのhandshake protocolでハッシュを計算する
	hasher := sha256.New()
	hasher.Write(serverProtocolBytes)
	messages := hasher.Sum(nil)

	result := prf(master, []byte(`client finished`), messages, 12)

	var record TLSRecordHeader
	record = record.NewTLSRecordHeader("Handshake")
	record.Length = uintTo2byte(40)

	var finish []byte
	finish = append(finish, toByteArr(record)...)
	finish = append(finish, result...)

	return finish
}
