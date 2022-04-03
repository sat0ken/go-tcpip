package main

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HMAC およびその擬似乱数関数
// https://www.ipa.go.jp/security/rfc/RFC5246-05JA.html
// https://atmarkit.itmedia.co.jp/ait/articles/0101/16/news002_4.html
// https://www.slideshare.net/shigeki_ohtsu/security-camp2015-tls
// https://github.com/shigeki/SecCamp2015-TLS/blob/master/MyMasterSecret.js
// データ拡張関数, あるsecretを必要なサイズまで伸長させる
func phash(secret, seed []byte) []byte {
	result := make([]byte, 48)
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
func createMasterSecret(premastersecret, clientServerRandom []byte) []byte {
	var seed []byte
	seed = append(seed, MasterSecretLable...)
	seed = append(seed, clientServerRandom...)
	return phash(premastersecret, seed)
}

func createFinishedMessage(premasterBytes MasterSecret, serverProtocolBytes []byte) []byte {
	var random []byte
	random = append(random, premasterBytes.ClientRandom...)
	random = append(random, premasterBytes.ServerRandom...)

	// master secretを作成する
	master := createMasterSecret(premasterBytes.PreMasterSecret, random)

	// サーバから受信したhandshake protocolでハッシュを計算する
	hasher := sha256.New()
	hasher.Write(serverProtocolBytes)
	messages := hasher.Sum(nil)

	seed := []byte(`client finished`)
	seed = append(seed, messages...)

	result := phash(master, seed)

	var record TLSRecordHeader
	record = record.NewTLSRecordHeader("Handshake")
	record.Length = uintTo2byte(40)

	var finish []byte
	finish = append(finish, toByteArr(record)...)
	finish = append(finish, result[0:40]...)

	return finish
}
