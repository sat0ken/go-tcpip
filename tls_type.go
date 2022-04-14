package main

import (
	"crypto/x509"
)

const (
	ContentTypeHandShake           = 0x16
	HandshakeTypeClientHello       = 0x01
	HandshakeTypeServerHello       = 0x02
	HandshakeTypeClientKeyExchange = 0x10 //=16
	HandshakeTypeServerCertificate = 0x0b //=11
	HandshakeTypeServerKeyExchange = 0x0c
	HandshakeTypeServerHelloDone   = 0x0e
	HandshakeTypeChangeCipherSpec  = 0x14 //=20
	HandshakeTypeFinished          = 0x14
)

var TLS1_2 = []byte{0x03, 0x03}

// 固定のラベル
var MasterSecretLable = []byte(`master secret`)
var KeyLable = []byte(`key expansion`)
var CLientFinished = []byte(`client finished`)
var ServerFinished = []byte(`server finished`)

// https://www.ipa.go.jp/security/rfc/RFC5246-AAJA.html
type TLSRecordHeader struct {
	ContentType     []byte
	ProtocolVersion []byte
	Length          []byte
}

type ServerHello struct {
	HandshakeType     []byte
	Length            []byte
	Version           []byte
	Random            []byte
	SessionID         []byte
	CipherSuites      []byte
	CompressionMethod []byte
}

type ServerCertificate struct {
	HandshakeType      []byte
	Length             []byte
	CertificatesLength []byte
	Certificates       []*x509.Certificate
}

// https://tex2e.github.io/rfc-translater/html/rfc8422.html
type ServerKeyExchange struct {
	HandshakeType               []byte
	Length                      []byte
	ECDiffieHellmanServerParams ECDiffieHellmanParam
}

type ServerHelloDone struct {
	HandshakeType []byte
	Length        []byte
}

type ClientHello struct {
	HandshakeType      []byte
	Length             []byte
	Version            []byte
	Random             []byte
	SessionIDLength    []byte
	SessionID          []byte
	CipherSuitesLength []byte
	CipherSuites       []byte
	CompressionLength  []byte
	CompressionMethod  []byte
	Extensions         []byte
}

// https://www.ipa.go.jp/security/rfc/RFC5246-07JA.html#0743
type ECDiffieHellmanParam struct {
	CurveType          []byte
	NamedCurve         []byte
	PubkeyLength       []byte
	Pubkey             []byte
	SignatureAlgorithm []byte
	SignatureLength    []byte
	Signature          []byte
}

type TLSProtocol struct {
	RHeader           TLSRecordHeader
	HandshakeProtocol interface{}
}

// https://qiita.com/n-i-e/items/41673fd16d7bd1189a29
type ClientKeyExchange struct {
	HandshakeType []byte
	Length        []byte

	// RSA
	EncryptedPreMasterSecretLength []byte
	EncryptedPreMasterSecret       []byte
	// ECDHE
	// PubkeyLength []byte
	// Pubkey []byte
}

type TCPandServerHello struct {
	ACKFromClient      TCPIP
	TLSProcotocol      []TLSProtocol
	TLSProcotocolBytes []byte
	ClientHelloRandom  []byte
}

type MasterSecret struct {
	PreMasterSecret []byte
	ServerRandom    []byte
	ClientRandom    []byte
}

type KeyBlock struct {
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientWriteIV  []byte
	ServerWriteIV  []byte
}
