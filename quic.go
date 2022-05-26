package tcpip

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"strconv"
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

func CreateQuicInitialSecret(dstConnId []byte) QuicKeyBlock {

	initSecret := hkdfExtract(dstConnId, initialSalt)
	clientInitSecret := hkdfExpandLabel(initSecret, clientInitialLabel, nil, 32)
	serverInitSecret := hkdfExpandLabel(initSecret, serverInitialLabel, nil, 32)

	return QuicKeyBlock{
		ClientKey:              hkdfExpandLabel(clientInitSecret, quicKeyLabel, nil, 16),
		ClientIV:               hkdfExpandLabel(clientInitSecret, quicIVLabel, nil, 12),
		ClientHeaderProtection: hkdfExpandLabel(clientInitSecret, quicHPLabel, nil, 16),
		ServerKey:              hkdfExpandLabel(serverInitSecret, quicKeyLabel, nil, 16),
		ServerIV:               hkdfExpandLabel(serverInitSecret, quicKeyLabel, nil, 12),
		ServerHeaderProtection: hkdfExpandLabel(serverInitSecret, quicHPLabel, nil, 16),
	}
}

// QUICパケットをパースする
func ParseRawQuicPacket(packet []byte, protected bool) interface{} {
	var i interface{}
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

		if protected {
			initPacket.Length = packet[0:2]
			initPacket.PacketNumber = packet[2:4]
			initPacket.Payload = packet[4:]
		} else {
			initPacket.Length = packet[0:2]
			initPacket.PacketNumber = packet[2:6]
			initPacket.Payload = packet[6:]
		}

		i = initPacket

	case "10":
		fmt.Println("Handshake Packet")
	}
	return i
}

// ヘッダ保護を解除したパケットにする
func ToUnprotecdQuicPacket(initpacket InitialPacket, packet []byte, keyblock QuicKeyBlock) []byte {
	// https://tex2e.github.io/blog/protocol/quic-initial-packet-decrypt
	// 5.4.2. ヘッダー保護のサンプル
	pnOffset := 7 + len(initpacket.DestConnID) + len(initpacket.SourceConnID) + len(initpacket.Length)
	pnOffset += len(initpacket.Token) + len(initpacket.TokenLength)
	sampleOffset := pnOffset + 4

	fmt.Printf("pnOffset is %d, sampleOffset is %d\n", pnOffset, sampleOffset)
	block, err := aes.NewCipher(keyblock.ClientHeaderProtection)
	if err != nil {
		log.Fatalf("ヘッダ保護解除エラー : %v\n", err)
	}
	sample := packet[sampleOffset : sampleOffset+16]
	encsample := make([]byte, len(sample))
	block.Encrypt(encsample, sample)

	packet[0] ^= encsample[0] & 0x0f
	pnlength := (packet[0] & 0x03) + 1

	a := packet[pnOffset : pnOffset+int(pnlength)]
	b := encsample[1 : 1+pnlength]
	for i, _ := range a {
		a[i] ^= b[i]
	}
	// 保護されていたパケット番号をセットし直す
	for i, _ := range a {
		packet[pnOffset+i] = a[i]
	}
	return packet
}

func DecryptQuicPayload(packetNumber, header, payload []byte, keyblock QuicKeyBlock) []byte {
	// パケット番号で12byteのnonceにする
	packetnum := extendArrByZero(packetNumber, len(keyblock.ClientIV))
	// clientivとxorする
	for i, _ := range packetnum {
		packetnum[i] ^= keyblock.ClientIV[i]
	}
	fmt.Printf("%x\n", packetnum)
	// AES-128-GCMで復号化する
	block, _ := aes.NewCipher(keyblock.ClientKey)
	aesgcm, _ := cipher.NewGCM(block)
	plaintext, err := aesgcm.Open(nil, packetnum, payload, header)
	if err != nil {
		log.Fatalf("DecryptQuicPayload is error : %v\n", err)
	}
	return plaintext
}

// 復号化されたQUICパケットのフレームをパースする
func ParseQuicFrame(packet []byte) (i interface{}) {
	switch packet[0] {
	case QuicFrameTypeCrypto:
		i = QuicCryptoFrame{
			Type:   packet[0:1],
			Offset: packet[1:3],
			Length: packet[3:4],
			Data:   packet[4 : 4+int(packet[3])],
			//Data: packet[4:],
		}
	}
	return i
}

func NewInitialPacket(finfo FrameInfo) []byte {
	var packet []byte

	infostr := finfo.HeaderForm
	infostr += finfo.FixedBit
	infostr += finfo.PacketType
	infostr += finfo.Reserved
	infostr += finfo.PacketNumberLegnth

	header0, _ := strconv.ParseUint(infostr, 2, 8)

	packet = append(packet, byte(header0))
	packet = append(packet, byte(header0))

	return packet
}
