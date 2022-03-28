package main

import "crypto/x509"

const (
	TypeClientHello       = 0x01
	TypeServerHello       = 0x02
	TypeClientKeyExchange = 0x10 //=16
	TypeCertificate       = 0x0b //=11
	TypeServerKeyExchange = 0x0c
	TypeServerHelloDone   = 0x0e
	TypeHandShake         = 0x16
)

var TLS1_2 = []byte{0x03, 0x03}

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

// https://www.moj.go.jp/ONLINE/CERTIFICATION/SYSTEM/system.html
// https://www.ipa.go.jp/security/rfc/RFC5280-00JA.html
type signedCertificate struct {
	version              []byte
	serialNumber         []byte
	signature            []byte
	issuer               []byte
	subject              []byte
	subjectPublickeyInfo []byte
}

type Certificate struct {
	length            []byte
	signedCertificate signedCertificate
}

type CertifiateProto struct {
	HandshakeType      []byte
	Length             []byte
	CertificatesLength []byte
	Certificates       []*x509.Certificate
}

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
	SessionID          []byte
	CipherSuitesLength []byte
	CipherSuites       []byte
	CompressionLength  []byte
	CompressionMethod  []byte
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
