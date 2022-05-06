package main

import (
	"crypto"
	"crypto/rsa"
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
	var key, iv, nonce []byte

	if tlsinfo.State == ContentTypeHandShake {
		key = tlsinfo.KeyBlockTLS13.serverHandshakeKey
		iv = tlsinfo.KeyBlockTLS13.serverHandshakeIV
		nonce = getNonce(tlsinfo.ServerHandshakeSeq, 8)
	} else {
		key = tlsinfo.KeyBlockTLS13.serverAppKey
		iv = tlsinfo.KeyBlockTLS13.serverAppIV
		nonce = getNonce(tlsinfo.ServerAppSeq, 8)
	}

	fmt.Printf("key is %x, iv is %x\n", key, iv)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatal(err)
	}

	xornonce := getXORNonce(nonce, iv)

	fmt.Printf("decrypt nonce is %x xornonce is %x, chipertext is %x, add is %x\n", nonce, xornonce, chipertext, header)
	plaintext, err := aead.Open(nil, xornonce, chipertext, header)
	if err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("plaintext is : %x\n", plaintext)
	return plaintext
}

func encryptChacha20(message []byte, tlsinfo TLSInfo) []byte {
	var key, iv, nonce []byte

	if tlsinfo.State == ContentTypeHandShake {
		key = tlsinfo.KeyBlockTLS13.clientHandshakeKey
		iv = tlsinfo.KeyBlockTLS13.clientHandshakeIV
		nonce = getNonce(tlsinfo.ClientHandshakeSeq, 8)
	} else {
		key = tlsinfo.KeyBlockTLS13.clientAppKey
		iv = tlsinfo.KeyBlockTLS13.clientAppIV
		nonce = getNonce(tlsinfo.ClientAppSeq, 8)
	}

	fmt.Printf("key is %x, iv is %x\n", key, iv)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatal(err)
	}
	//nonce := getNonce(tlsinfo.ClientSequenceNum, 8)
	xornonce := getXORNonce(nonce, iv)
	header := strtoByte("170303")
	totalLength := len(message) + 16

	header = append(header, uintTo2byte(uint16(totalLength))...)

	fmt.Printf("encrypt now nonce is %x xornonce is %x, plaintext is %x, add is %x\n", nonce, xornonce, message, header)
	ciphertext := aead.Seal(header, xornonce, message, header)

	//fmt.Printf("plaintext is : %x\n", plaintext)
	return ciphertext
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
	// labelを作成
	tlslabel := []byte(`tls13 `)
	tlslabel = append(tlslabel, label...)

	// lengthをセット
	hkdflabel := uintTo2byte(uint16(length))
	hkdflabel = append(hkdflabel, byte(len(tlslabel)))
	hkdflabel = append(hkdflabel, tlslabel...)

	hkdflabel = append(hkdflabel, byte(len(ctx)))
	hkdflabel = append(hkdflabel, ctx...)

	return hkdfExpand(secret, hkdflabel, length)
}

func deriveSecret(secret, label, messages_byte []byte) []byte {
	return hkdfExpandLabel(secret, label, messages_byte, 32)
}

func keyscheduleToMasterSecret(sharedkey, handshake_messages []byte) KeyBlockTLS13 {

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
	fmt.Printf("CLIENT_HANDSHAKE_TRAFFIC_SECRET %x %x\n", zero, chstraffic)

	// Finished message用のキー
	clientfinkey := deriveSecret(chstraffic, FinishedLabel, nil)
	//fmt.Printf("clientfinkey is : %x\n", clientfinkey)

	// {client} derive secret "tls13 s hs traffic":
	shstraffic := deriveSecret(handshake_secret, ServerhsTraffic, hash_messages)
	fmt.Printf("SERVER_HANDSHAKE_TRAFFIC_SECRET %x %x\n", zero, shstraffic)

	// Finished message用のキー
	serverfinkey := deriveSecret(shstraffic, FinishedLabel, nil)
	//fmt.Printf("serverfinkey is : %x\n", serverfinkey)

	derivedSecretFormaster := deriveSecret(handshake_secret, DerivedLabel, zerohash)
	fmt.Printf("derivedSecretFormaster is : %x\n", derivedSecretFormaster)

	extractSecretMaster := hkdfExtract(zero, derivedSecretFormaster)
	fmt.Printf("extractSecretMaster is : %x\n", extractSecretMaster)

	// {client} derive write traffic keys for handshake data from server hs traffic:
	// 7.3. トラフィックキーの計算
	clienttraffickey := hkdfExpandLabel(chstraffic, []byte(`key`), nil, 32)
	fmt.Printf("client traffic key is : %x\n", clienttraffickey)

	clienttrafficiv := hkdfExpandLabel(chstraffic, []byte(`iv`), nil, 12)
	fmt.Printf("client traffic iv is : %x\n", clienttrafficiv)

	servertraffickey := hkdfExpandLabel(shstraffic, []byte(`key`), nil, 32)
	fmt.Printf("server traffic key is : %x\n", servertraffickey)

	servertrafficiv := hkdfExpandLabel(shstraffic, []byte(`iv`), nil, 12)
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

func keyscheduleToAppTraffic(tlsinfo TLSInfo) TLSInfo {
	hash_messages := writeHash(tlsinfo.Handshakemessages)
	fmt.Printf("hashed messages is %x\n", hash_messages)

	zero := noRandomByte(32)

	// {client} derive secret "tls13 c ap traffic":
	captraffic := deriveSecret(tlsinfo.KeyBlockTLS13.masterSecret, ClientapTraffic, hash_messages)
	fmt.Printf("CLIENT_TRAFFIC_SECRET_0 %x %x\n", zero, captraffic)
	saptraffic := deriveSecret(tlsinfo.KeyBlockTLS13.masterSecret, ServerapTraffic, hash_messages)
	fmt.Printf("SERVER_TRAFFIC_SECRET_0 %x %x\n", zero, saptraffic)

	// 7.3. トラフィックキーの計算, Application用
	tlsinfo.KeyBlockTLS13.clientAppKey = hkdfExpandLabel(captraffic, []byte(`key`), nil, 32)
	tlsinfo.KeyBlockTLS13.clientAppIV = hkdfExpandLabel(captraffic, []byte(`iv`), nil, 12)
	fmt.Printf("clientAppKey and IV is : %x, %x\n", tlsinfo.KeyBlockTLS13.clientAppKey, tlsinfo.KeyBlockTLS13.clientAppIV)

	tlsinfo.KeyBlockTLS13.serverAppKey = hkdfExpandLabel(saptraffic, []byte(`key`), nil, 32)
	tlsinfo.KeyBlockTLS13.serverAppIV = hkdfExpandLabel(saptraffic, []byte(`iv`), nil, 12)
	fmt.Printf("serverAppkey and IV is : %x, %x\n", tlsinfo.KeyBlockTLS13.serverAppKey, tlsinfo.KeyBlockTLS13.serverAppIV)

	return tlsinfo
}

// 4.4.3. Certificate Verify
func verifyServerCertificate(pubkey *rsa.PublicKey, signature, handshake_messages []byte) {
	hash_messages := writeHash(handshake_messages)

	hasher := sha256.New()
	hasher.Write(strtoByte(str0x20x64))
	hasher.Write(serverCertificateContextString)
	hasher.Write([]byte{0x00})
	hasher.Write(hash_messages)
	signed := hasher.Sum(nil)
	fmt.Printf("hash_messages is %x, signed is %x\n", hash_messages, signed)

	signOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	err := rsa.VerifyPSS(pubkey, crypto.SHA256, signed, signature, signOpts)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Server Certificate Verify is OK !!")
}
