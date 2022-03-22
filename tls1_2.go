package main

const (
	ClientHello       = 0x01
	ClientKeyExchange = 0x10 //=16

)

var TLS1_2 = []byte{0x03, 0x03}

// https://www.ipa.go.jp/security/rfc/RFC5246-AAJA.html
type TLSRecordHeader struct {
	ContentType     []byte
	ProtocolVersion []byte
	Length          []byte
}

type TLSHandshake struct {
	HandshakeType      []byte
	Length             []byte
	Version            []byte
	Random             []byte
	SessionID          []byte
	CipherSuitesLength []byte
	CipherSuites       []byte
	CompressionLength  []byte
	CompressionMethod  []byte
	ExtensionLength    []byte
	Extension          []byte
}

func NewTLSRecordHeader(ctype string) TLSRecordHeader {
	var ctypeByte byte
	switch ctype {
	case "Handshake":
		ctypeByte = byte(22)
	case "AppDada":
		ctypeByte = byte(23)
	case "Alert":
		ctypeByte = byte(21)
	case "ChangeCipherSpec":
		ctypeByte = byte(20)
	}
	return TLSRecordHeader{
		ContentType: []byte{ctypeByte},
		// TLS 1.2
		ProtocolVersion: TLS1_2,
		Length:          []byte{0x00, 0x00},
	}
}

func NewClientHello(hstype string) TLSHandshake {

	cipher := getChipersList()

	handshake := TLSHandshake{
		HandshakeType:      []byte{ClientHello},
		Length:             []byte{0x00, 0x00, 0x00},
		Version:            TLS1_2,
		Random:             random32byte(),
		SessionID:          []byte{0x00},
		CipherSuitesLength: []byte{byte(len(cipher))},
		CipherSuites:       cipher,
		CompressionLength:  []byte{0x01},
		CompressionMethod:  []byte{0x00},
	}

	return handshake
}
