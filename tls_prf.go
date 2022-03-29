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
