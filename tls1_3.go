package main

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"io"
	"log"
)

func genrateClientECDHESharedKey() ECDHEKeys {
	// 秘密鍵となる32byteの乱数をセット
	//clientPrivateKey := randomByte(curve25519.ScalarSize)
	clientPrivateKey := noRandomByte(32)

	// ClientKeyExchangeでサーバに送る公開鍵を生成
	clientPublicKey, _ := curve25519.X25519(clientPrivateKey, curve25519.Basepoint)

	return ECDHEKeys{
		privateKey: clientPrivateKey,
		publicKey:  clientPublicKey,
	}
}

// golangのclientのをキャプチャしてそのままセットする
func setTLS1_3Extension() ([]byte, ECDHEKeys) {
	var tlsExtension []byte

	// set length
	tlsExtension = append(tlsExtension, []byte{0x00, 0x6F}...)

	//　status_reqeust
	tlsExtension = append(tlsExtension, []byte{0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00}...)

	// supported_groups
	tlsExtension = append(tlsExtension, []byte{0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d}...)

	// ec_point_formats
	tlsExtension = append(tlsExtension, []byte{0x00, 0x0b, 0x00, 0x02, 0x01, 0x00}...)

	// signature_algorithms
	tlsExtension = append(tlsExtension, []byte{
		0x00, 0x0d, 0x00, 0x1a, 0x00, 0x18, 0x08, 0x04,
		0x04, 0x03, 0x08, 0x07, 0x08, 0x05, 0x08, 0x06,
		0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x05, 0x03,
		0x06, 0x03, 0x02, 0x01, 0x02, 0x03,
	}...)

	// renagotiation_info
	tlsExtension = append(tlsExtension, []byte{0xff, 0x01, 0x00, 0x01, 0x00}...)
	// signed_certificate_timestamp
	tlsExtension = append(tlsExtension, []byte{0x00, 0x12, 0x00, 0x00}...)
	// supported_versions
	tlsExtension = append(tlsExtension, []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}...)

	// 共通鍵を生成する
	clientkey := genrateClientECDHESharedKey()

	// key_share, DHEの公開鍵を送る
	tlsExtension = append(tlsExtension, []byte{0x00, 0x33, 0x00, 0x26, 0x00, 0x24}...)
	tlsExtension = append(tlsExtension, uintTo2byte(uint16(tls.X25519))...)

	// keyのLength = 32byte
	tlsExtension = append(tlsExtension, []byte{0x00, 0x20}...)
	// 共通鍵を追加
	tlsExtension = append(tlsExtension, clientkey.publicKey...)

	return tlsExtension, clientkey
}

// https://pkg.go.dev/golang.org/x/crypto@v0.0.0-20220411220226-7b82a4e95df4/chacha20poly1305
func decryptChacha20(message []byte, tlsinfo TLSInfo) []byte {
	header := message[0:5]
	chipertext := message[5:]
	var key, iv []byte

	if tlsinfo.State == "Handshake" {
		key = tlsinfo.KeyBlockTLS13.serverHandshakeKey
		iv = tlsinfo.KeyBlockTLS13.serverHandshakeIV
	} else {
		key = tlsinfo.KeyBlockTLS13.serverAppKey
		iv = tlsinfo.KeyBlockTLS13.serverAppIV
	}

	//fmt.Printf("key is %x\n", key)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatal(err)
	}
	nonce := getNonce(tlsinfo.ClientSequenceNum, 8)
	xornonce := getXORNonce(nonce, iv)

	fmt.Printf("decrypt now nonce is %x, cipertext is %x, add is %x\n", xornonce, chipertext, header)
	plaintext, err := aead.Open(nil, xornonce, chipertext, header)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("plaintext is : %x\n", plaintext)
	return plaintext
}

// HKDF-Extractは、上部からSalt引数を、左側からIKM引数を取り
func hkdfExtract(secret, salt []byte) []byte {
	hash := sha256.New
	return hkdf.Extract(hash, secret, salt)
}

func hkdfExpand(secret, hkdflabel []byte, length int) []byte {
	hash := sha256.New
	expand := hkdf.Expand(hash, secret, hkdflabel)
	b := make([]byte, length)
	io.ReadFull(expand, b)

	return b
}

func hkdfExpandLabel(secret, label, ctx []byte, length int) []byte {

	tlslabel := []byte(`tls13 `)
	tlslabel = append(tlslabel, label...)

	hkdflabel := uintTo2byte(uint16(length))
	hkdflabel = append(hkdflabel, byte(len(tlslabel)))
	hkdflabel = append(hkdflabel, tlslabel...)

	hkdflabel = append(hkdflabel, byte(len(ctx)))
	hkdflabel = append(hkdflabel, ctx...)

	//fmt.Printf("hkdflabel is : %x\n", hkdflabel)

	return hkdfExpand(secret, hkdflabel, length)
}

func deriveSecret(secret, label, messages_byte []byte) []byte {
	return hkdfExpandLabel(secret, label, messages_byte, 32)
}

func keyscheduleTLS13(sharedkey, handshake_messages []byte) KeyBlockTLS13 {

	zero := noRandomByte(32)
	zerohash := writeHash(nil)
	earlySecret := hkdfExtract(zero, zero)

	// {client} derive secret for handshake "tls13 derived"
	derivedSecretForhs := deriveSecret(earlySecret, DerivedLabel, zerohash)
	fmt.Printf("derivedSecretForhs %x\n", derivedSecretForhs)

	// {client} extract secret "handshake":
	handshake_secret := hkdfExtract(sharedkey, derivedSecretForhs)
	fmt.Printf("handshake_secret is : %x\n", handshake_secret)

	hash_messages := writeHash(handshake_messages)
	fmt.Printf("hashed messages is %x\n", hash_messages)

	// {client} derive secret "tls13 c hs traffic":
	chstraffic := deriveSecret(handshake_secret, ClienthsTraffic, hash_messages)
	fmt.Printf("chstraffic is : %x\n", chstraffic)

	// Finished message用のキー
	clientfinkey := deriveSecret(chstraffic, Finished, nil)
	fmt.Printf("clientfinkey is : %x\n", clientfinkey)

	// {client} derive secret "tls13 s hs traffic":
	shstraffic := deriveSecret(handshake_secret, ServerhsTraffic, hash_messages)
	fmt.Printf("shstraffic is : %x\n", shstraffic)

	// Finished message用のキー
	serverfinkey := deriveSecret(shstraffic, Finished, nil)
	fmt.Printf("serverfinkey is : %x\n", serverfinkey)

	derivedSecretFormaster := deriveSecret(handshake_secret, DerivedLabel, zerohash)
	fmt.Printf("derivedSecretFormaster is : %x\n", derivedSecretFormaster)

	extractSecretMaster := hkdfExtract(zero, derivedSecretFormaster)
	fmt.Printf("extractSecretMaster is : %x\n", extractSecretMaster)

	// {client} derive write traffic keys for handshake data from server hs traffic:
	// 7.3. トラフィックキーの計算
	clienttraffickey := hkdfExpandLabel(chstraffic, []byte(`key`), strtoByte(""), 32)
	fmt.Printf("client traffic key is : %x\n", clienttraffickey)

	clienttrafficiv := hkdfExpandLabel(chstraffic, []byte(`iv`), strtoByte(""), 12)
	fmt.Printf("client traffic iv is : %x\n", clienttrafficiv)

	servertraffickey := hkdfExpandLabel(shstraffic, []byte(`key`), strtoByte(""), 32)
	fmt.Printf("server traffic key is : %x\n", servertraffickey)

	servertrafficiv := hkdfExpandLabel(shstraffic, []byte(`iv`), strtoByte(""), 12)
	fmt.Printf("server traffic iv is : %x\n", servertrafficiv)

	return KeyBlockTLS13{
		handshakeSecret:       handshake_secret,
		clientHandshakeSecret: chstraffic,
		clientHandshakeKey:    clienttraffickey,
		clientHandshakeIV:     clienttrafficiv,
		clientFinishedKey:     clientfinkey,
		serverHandshakeSecret: shstraffic,
		serverHandshakeKey:    servertraffickey,
		serverHandshakeIV:     servertrafficiv,
		serverFinishedKey:     serverfinkey,
		masterSecret:          extractSecretMaster,
	}
}