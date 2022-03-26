package main

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

type signedCertificate struct {
	signature            []byte
	issuer               []byte
	subject              []byte
	subjectPublickeyInfo []byte
}

type Certificate struct {
	signedCertificate signedCertificate
}

type TLSCertificate struct {
	Length      []byte
	Certificate Certificate
}

type CertifiateProto struct {
	HandshakeType      []byte
	Length             []byte
	CertificatesLength []byte
	Certificates       []TLSCertificate
}

type ServerKeyExchange struct {
	HandshakeType               []byte
	Length                      []byte
	ECDiffieHellmanServerParams []byte
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
