package main

import (
	"crypto/x509"
)

const (
	ContentTypeHandShake             = 0x16
	ContentTypeAlert                 = 0x15
	ContentTypeApplicationData       = 0x17
	HandshakeTypeClientHello         = 0x01
	HandshakeTypeServerHello         = 0x02
	HandshakeTypeEncryptedExtensions = 0x08
	HandshakeTypeClientKeyExchange   = 0x10 //=16
	HandshakeTypeCertificate         = 0x0b //=11
	HandshakeTypeServerKeyExchange   = 0x0c
	HandshakeTypeCertificateRequest  = 0x0d
	HandshakeTypeServerHelloDone     = 0x0e
	HandshakeTypeCertificateVerify   = 0x0f
	HandshakeTypeChangeCipherSpec    = 0x14 //=20
	HandshakeTypeFinished            = 0x14
	CurveIDx25519                    = 0x1D
)

var TLS1_2 = []byte{0x03, 0x03}
var TLS1_3 = []byte{0x03, 0x04}

// 固定のラベル
var MasterSecretLable = []byte(`master secret`)
var KeyLable = []byte(`key expansion`)
var CLientFinishedLabel = []byte(`client finished`)
var ServerFinishedLabel = []byte(`server finished`)

// TLS1.3
var DerivedLabel = []byte(`derived`)
var ClienthsTraffic = []byte(`c hs traffic`)
var ServerhsTraffic = []byte(`s hs traffic`)
var Finished = []byte(`finished`)

// https://www.ipa.go.jp/security/rfc/RFC5246-AAJA.html
type TLSRecordHeader struct {
	ContentType     []byte
	ProtocolVersion []byte
	Length          []byte
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

type ServerHello struct {
	HandshakeType     []byte
	Length            []byte
	Version           []byte
	Random            []byte
	SessionIDLength   []byte
	SessionID         []byte
	CipherSuites      []byte
	CompressionMethod []byte
	ExtensionLength   []byte
	TLSExtensions     []TLSExtensions
}

type TLSExtensions struct {
	Type   []byte
	Length []byte
	Value  interface{}
}

type ServerCertificate struct {
	HandshakeType                    []byte
	Length                           []byte
	CertificatesRequestContextLength []byte
	CertificatesLength               []byte
	Certificates                     []*x509.Certificate
}

// https://tex2e.github.io/rfc-translater/html/rfc8422.html
type ServerKeyExchange struct {
	HandshakeType               []byte
	Length                      []byte
	ECDiffieHellmanServerParams ECDiffieHellmanParam
}

type CertificateRequest struct {
	HandshakeType                 []byte
	Length                        []byte
	CertificateTypesCount         []byte
	CertificateTypes              []byte
	SignatureHashAlgorithmsLength []byte
	SignatureHashAlgorithms       []byte
}

type ClientCertificate struct {
	HandshakeType      []byte
	Length             []byte
	CertificatesLength []byte
	CertificateLength  []byte
	Certificate        []byte
}

// https://qiita.com/n-i-e/items/41673fd16d7bd1189a29
type ClientKeyExchange struct {
	HandshakeType []byte
	Length        []byte
	// RSA
	EncryptedPreMasterSecretLength []byte
	EncryptedPreMasterSecret       []byte
	// ECDHE
	PubkeyLength []byte
	Pubkey       []byte
}

type CertificateVerify struct {
	HandshakeType           []byte
	Length                  []byte
	SignatureHashAlgorithms []byte
	SignatureLength         []byte
	Signature               []byte
}

type ServerHelloDone struct {
	HandshakeType []byte
	Length        []byte
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

type TCPandServerHello struct {
	ACKFromClient      TCPIP
	TLSProcotocol      []TLSProtocol
	TLSProcotocolBytes []byte
	ClientHelloRandom  []byte
}

type MasterSecretInfo struct {
	MasterSecret    []byte
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

type TLSInfo struct {
	State             string
	Version           []byte
	MasterSecretInfo  MasterSecretInfo
	KeyBlock          KeyBlock
	KeyBlockTLS13     KeyBlockTLS13
	Handshakemessages []byte
	ClientSequenceNum int
	ECDHEKeys         ECDHEKeys
}

type ECDHEKeys struct {
	privateKey []byte
	publicKey  []byte
	sharedKey  []byte
}

type KeyBlockTLS13 struct {
	handshakeSecret       []byte
	clientHandshakeSecret []byte
	clientHandshakeKey    []byte
	clientHandshakeIV     []byte
	clientFinishedKey     []byte
	serverHandshakeSecret []byte
	serverHandshakeKey    []byte
	serverHandshakeIV     []byte
	serverFinishedKey     []byte
	masterSecret          []byte
	clientAppSecret       []byte
	clientAppKey          []byte
	clientAppIV           []byte
	serverAppSecret       []byte
	serverAppKey          []byte
	serverAppIV           []byte
}

type EncryptedExtensions struct {
	HandshakeType   []byte
	Length          []byte
	ExtensionLength []byte
	TLSExtensions   []TLSExtensions
}
