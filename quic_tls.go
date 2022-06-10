package tcpip

import "crypto/tls"

func (*ClientHello) NewQuicClientHello() (TLSInfo, []byte) {
	var tlsinfo TLSInfo
	handshake := ClientHello{
		HandshakeType:      []byte{HandshakeTypeClientHello},
		Length:             []byte{0x00, 0x00, 0x00},
		Version:            TLS1_2,
		Random:             noRandomByte(32),
		SessionIDLength:    []byte{0x00},
		CipherSuitesLength: []byte{0x00, 0x02},
		// TLS_CHACHA20_POLY1305_SHA256
		//CipherSuites: []byte{0x13, 0x03},
		// TLS_RSA_WITH_AES_128_GCM_SHA256
		CipherSuites: []byte{0x13, 0x01},
		// ECDHE-RSA-AES128-GCM-SHA256
		//CipherSuites:      []byte{0xC0, 0x2F},
		CompressionLength: []byte{0x01},
		CompressionMethod: []byte{0x00},
	}

	// TLS1.3のextensionをセット
	handshake.Extensions, tlsinfo.ECDHEKeys = setQuicTLSExtension()
	// Quic transport parameterを追加
	handshake.Extensions = append(handshake.Extensions, setQuicTransportParameters()...)

	// Typeの1byteとLengthの3byteを合計から引く
	handshake.Length = UintTo3byte(uint32(toByteLen(handshake) - 4))
	// byteにする
	handshakebyte := toByteArr(handshake)

	var hello []byte
	hello = append(hello, NewTLSRecordHeader("Handshake", toByteLen(handshake))...)
	hello = append(hello, handshakebyte...)

	// ClientHelloを保存しておく
	tlsinfo.Handshakemessages = handshakebyte

	return tlsinfo, hello
}

// quic-goが送っていたのをセットする
func setQuicTransportParameters() []byte {
	var quicParams []byte
	var quicParamsBytes []byte

	quicParams = append(quicParams, initialMaxStreamDataBidiLocal...)
	quicParams = append(quicParams, initialMaxStreamDataBidiRemote...)
	quicParams = append(quicParams, initialMaxStreamDataUni...)
	quicParams = append(quicParams, initialMaxData...)
	quicParams = append(quicParams, initialMaxStreamsBidi...)
	quicParams = append(quicParams, initialMaxStreamsUni...)
	quicParams = append(quicParams, maxIdleTimeout...)
	quicParams = append(quicParams, maxUdpPayloadSize...)
	quicParams = append(quicParams, disableActiveMigration...)
	quicParams = append(quicParams, activeConnectionIdLimit...)
	quicParams = append(quicParams, initialSourceConnectionId...)
	quicParams = append(quicParams, maxDatagramFrameSize...)

	// Type = 57 をセット
	quicParamsBytes = append(quicParamsBytes, []byte{0x00, 0x39}...)
	// Lengthをセット
	quicParamsBytes = append(quicParamsBytes, UintTo2byte(uint16(len(quicParams)))...)
	quicParamsBytes = append(quicParamsBytes, quicParams...)

	return quicParamsBytes
}

// golangのclientのをキャプチャしてそのままセットする
func setQuicTLSExtension() ([]byte, ECDHEKeys) {
	var tlsExtension []byte
	var tlsExtensionByte []byte

	// server_name
	tlsExtension = append(tlsExtension, []byte{0x00, 0x00, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x00,
		0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
		0x73, 0x74}...)

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

	// Application Layer Protocol Negotiation
	tlsExtension = append(tlsExtension, []byte{0x00, 0x10, 0x00, 0x14, 0x00, 0x12, 0x11, 0x71,
		0x75, 0x69, 0x63, 0x2d, 0x65, 0x63, 0x68, 0x6f,
		0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65}...)

	// signed_certificate_timestamp
	tlsExtension = append(tlsExtension, []byte{0x00, 0x12, 0x00, 0x00}...)
	// supported_versions
	tlsExtension = append(tlsExtension, []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}...)

	// 共通鍵を生成する
	clientkey := genrateClientECDHEKey()

	// key_share, DHEの公開鍵を送る
	tlsExtension = append(tlsExtension, []byte{0x00, 0x33, 0x00, 0x26, 0x00, 0x24}...)
	tlsExtension = append(tlsExtension, UintTo2byte(uint16(tls.X25519))...)
	// keyのLength = 32byte
	tlsExtension = append(tlsExtension, []byte{0x00, 0x20}...)
	// 公開鍵を追加
	tlsExtension = append(tlsExtension, clientkey.PublicKey...)

	// set length
	tlsExtensionByte = append(tlsExtensionByte, UintTo2byte(uint16(len(tlsExtension)))...)
	tlsExtensionByte = append(tlsExtensionByte, tlsExtension...)

	return tlsExtensionByte, clientkey
}
