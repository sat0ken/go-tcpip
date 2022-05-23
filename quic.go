package tcpip

import (
	"bytes"
	"fmt"
)

var initialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// 固定のラベル
var clientInitialLabel = []byte(`client in`)
var serverInitialLabel = []byte(`server in`)
var quicKeyLabel = []byte(`quic key`)
var quicIVLabel = []byte(`quic iv`)

// hp is for header protection
var quicHPLabel = []byte(`quic hp`)

func CreateQuicInitialSecret(dstConnId []byte) {
	initSecret := hkdfExtract(dstConnId, initialSalt)
	fmt.Printf("initSecret is  %x\n", initSecret)
	clientInitSecret := hkdfExpandLabel(initSecret, clientInitialLabel, nil, 32)
	clientKey := hkdfExpandLabel(clientInitSecret, quicKeyLabel, nil, 16)
	clientIV := hkdfExpandLabel(clientInitSecret, quicIVLabel, nil, 12)
	clientHP := hkdfExpandLabel(clientInitSecret, quicHPLabel, nil, 16)

	fmt.Printf("clientInitSecret is  %x\n", clientInitSecret)
	fmt.Printf("clientKey is  %x\n", clientKey)
	fmt.Printf("clientIV is  %x\n", clientIV)
	fmt.Printf("clientHP is  %x\n", clientHP)
}

func ParseQUIC(packet []byte) {
	p0 := fmt.Sprintf("%08b", packet[0])
	switch p0[2:4] {
	case "00":
		finfo := FrameInfo{
			HeaderForm:         p0[0:1],
			FixedBit:           p0[1:2],
			PacketType:         p0[2:4],
			Reserved:           p0[4:6],
			PacketNumberLegnth: p0[6:],
		}

		initPacket := InitialPacket{
			FrameInfo:        finfo,
			Version:          packet[1:5],
			DestConnIDLength: packet[5:6],
		}
		initPacket.DestConnID = packet[6 : 6+int(initPacket.DestConnIDLength[0])]
		// packetを縮める
		packet = packet[6+int(initPacket.DestConnIDLength[0]):]

		// SourceID Connection Lengthが0なら
		if bytes.Equal(packet[0:1], []byte{0x00}) {
			initPacket.SourceConnIDLength = packet[0:1]
			// packetを縮める
			packet = packet[1:]
		} else {
			initPacket.SourceConnIDLength = packet[0:1]
			initPacket.SourceConnID = packet[:1+int(initPacket.SourceConnID[0])]
			// packetを縮める
			packet = packet[1+int(initPacket.SourceConnID[0]):]
		}

		// Token Lengthが0なら
		if bytes.Equal(packet[0:1], []byte{0x00}) {
			initPacket.TokenLength = packet[0:1]
			// packetを縮める
			packet = packet[1:]
		} else {
			initPacket.TokenLength = packet[0:1]
			initPacket.Token = packet[:1+int(initPacket.TokenLength[0])]
			// packetを縮める
			packet = packet[1+int(initPacket.TokenLength[0]):]
		}

		initPacket.Length = packet[0:2]

		initPacket.PacketNumber = packet[2:4]
		initPacket.Payload = packet[4:]

		//fmt.Printf("Packet is %x\n", packet)
		//fmt.Printf("Initial Packet is %+v\n", initPacket)

		// 5.4.2. ヘッダー保護のサンプル
		pnOffset := 7 + len(initPacket.DestConnID) + len(initPacket.SourceConnID) + len(initPacket.Length)
		pnOffset += len(initPacket.Token) + len(initPacket.TokenLength)
		sampleOffset := pnOffset + 4

		fmt.Printf("pnOffset is %d, sampleOffset is %d\n", pnOffset, sampleOffset)

	case "10":
		fmt.Println("Handshake Packet")
	}
}
