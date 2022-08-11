package tcpip

import (
	"crypto/tls"
)

func (*ClientHello) NewQuicClientHello(sourceConnID []byte) (TLSInfo, []byte) {
	var tlsinfo TLSInfo
	handshake := ClientHello{
		HandshakeType:      []byte{HandshakeTypeClientHello},
		Length:             []byte{0x00, 0x00, 0x00},
		Version:            TLS1_2,
		Random:             noRandomByte(32),
		SessionIDLength:    []byte{0x00},
		CipherSuitesLength: []byte{0x00, 0x26},
		// TLS_CHACHA20_POLY1305_SHA256
		//CipherSuites: []byte{0x13, 0x03},
		// TLS_RSA_WITH_AES_128_GCM_SHA256
		// 19 suites
		CipherSuites: []byte{
			0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
			0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x09, 0xc0, 0x13,
			0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d,
			0x00, 0x2f, 0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a,
			0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
		},
		// ECDHE-RSA-AES128-GCM-SHA256
		//CipherSuites:      []byte{0xC0, 0x2F},
		CompressionLength: []byte{0x01},
		CompressionMethod: []byte{0x00},
	}

	// TLS1.3のextensionをセット
	handshake.Extensions, tlsinfo.ECDHEKeys = setQuicTLSExtension()
	// Quic transport parameterを追加
	handshake.Extensions = append(handshake.Extensions, setQuicTransportParameters(sourceConnID)...)
	// ExtensionLengthをセット
	handshake.ExtensionLength = UintTo2byte(uint16(len(handshake.Extensions)))

	// Typeの1byteとLengthの3byteを合計から引く
	handshake.Length = UintTo3byte(uint32(toByteLen(handshake) - 4))
	// byteにする
	handshakebyte := toByteArr(handshake)

	//var hello []byte
	//hello = append(hello, NewTLSRecordHeader("Handshake", toByteLen(handshake))...)
	//hello = append(hello, handshakebyte...)

	// ClientHelloを保存しておく
	tlsinfo.Handshakemessages = handshakebyte

	return tlsinfo, handshakebyte
}

// quic-goが送っていたのをセットする
func setQuicTransportParameters(sourceConnID []byte) []byte {
	var quicParams []byte
	var quicParamsBytes []byte

	// GREASE
	quicParams = append(quicParams, []byte{0x41, 0x8f, 0x03, 0x9c, 0xcd, 0x14}...)
	quicParams = append(quicParams, initialMaxStreamDataBidiLocal...)
	quicParams = append(quicParams, initialMaxStreamDataBidiRemote...)
	quicParams = append(quicParams, initialMaxStreamDataUni...)
	quicParams = append(quicParams, initialMaxData...)
	quicParams = append(quicParams, initialMaxStreamsBidi...)
	quicParams = append(quicParams, initialMaxStreamsUni...)
	quicParams = append(quicParams, maxIdleTimeout...)
	quicParams = append(quicParams, maxUdpPayloadSize...)
	// GREASE
	quicParams = append(quicParams, []byte{0x0b, 0x01, 0x1a}...)
	quicParams = append(quicParams, disableActiveMigration...)
	quicParams = append(quicParams, activeConnectionIdLimit...)

	// Set source connection id Length
	initialSourceConnectionId = append(initialSourceConnectionId, byte(len(sourceConnID)))
	// Set source connection id
	initialSourceConnectionId = append(initialSourceConnectionId, sourceConnID...)

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

	// server_name
	//tlsExtension = append(tlsExtension, []byte{
	//	0x00, 0x00, 0x00, 0x0f, 0x00, 0x0d, 0x00, 0x00,
	//	0x0a, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	//	0x63, 0x6f, 0x6d}...)

	//　status_reqeust
	tlsExtension = append(tlsExtension, []byte{0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00}...)

	// supported_groups
	tlsExtension = append(tlsExtension, []byte{0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d,
		0x00, 0x17, 0x00, 0x18, 0x00, 0x19}...)

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
	tlsExtension = append(tlsExtension, []byte{0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33}...)

	// signed_certificate_timestamp
	tlsExtension = append(tlsExtension, []byte{0x00, 0x12, 0x00, 0x00}...)

	// supported_versions
	tlsExtension = append(tlsExtension, []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}...)

	// 共通鍵を生成する
	clientkey := genrateClientECDHEKey()

	// key_share, DHEの公開鍵を送る
	// Type=0x0033, Length=0x0026, ClientKeyShareLength=0x0024
	tlsExtension = append(tlsExtension, []byte{0x00, 0x33, 0x00, 0x26, 0x00, 0x24}...)
	// Group=0x001d
	tlsExtension = append(tlsExtension, UintTo2byte(uint16(tls.X25519))...)
	// keyのLength = 32byte
	tlsExtension = append(tlsExtension, []byte{0x00, 0x20}...)
	// 公開鍵を追加
	//tlsExtension = append(tlsExtension, clientkey.PublicKey...)
	tlsExtension = append(tlsExtension, strtoByte("2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74")...)

	// set length
	//tlsExtensionByte = append(tlsExtensionByte, UintTo2byte(uint16(len(tlsExtension)))...)
	//tlsExtensionByte = append(tlsExtensionByte, tlsExtension...)

	return tlsExtension, clientkey
}

func ParseQuicTLSHandshake(packet []byte) interface{} {
	var i interface{}

	switch packet[0] {
	case HandshakeTypeServerHello:
		hello := ServerHello{
			HandshakeType:     packet[0:1],
			Length:            packet[1:4],
			Version:           packet[4:6],
			Random:            packet[6:38],
			SessionIDLength:   packet[38:39],
			CipherSuites:      packet[39:41],
			CompressionMethod: packet[41:42],
			ExtensionLength:   packet[42:44],
		}
		// Memo: Googleのサーバはkey_share, supported_versionの順番でTLS Extensionsが送られてくる模様
		// Todo: Extensionsをパースする関数を作らないと順番入れ替ってパースできなくて草
		// key_share
		hello.TLSExtensions = append(hello.TLSExtensions, TLSExtensions{
			Type:   packet[44:46],
			Length: packet[46:48],
			Value: map[string]interface{}{
				"Group":             packet[48:50],
				"KeyExchangeLength": packet[50:52],
				"KeyExchange":       packet[52:84],
			},
		})
		// supported_versions
		hello.TLSExtensions = append(hello.TLSExtensions, TLSExtensions{
			Type:   packet[84:86],
			Length: packet[86:88],
			Value:  packet[88:90],
		})
		i = hello

	}

	return i
}
