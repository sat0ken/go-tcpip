package tcpip

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"strconv"
)

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
func ParseRawQuicPacket(packet []byte, protected bool) (rawpacket QuicRawPacket) {

	p0 := fmt.Sprintf("%08b", packet[0])
	switch p0[2:4] {
	case "00":
		//finfo := FrameInfo{
		//	HeaderForm:         p0[0:1],
		//	FixedBit:           p0[1:2],
		//	PacketType:         p0[2:4],
		//	Reserved:           p0[4:6],
		//	PacketNumberLegnth: p0[6:],
		//}

		commonHeader := QuicLongCommonHeader{
			FrameByte:        packet[0:1],
			Version:          packet[1:5],
			DestConnIDLength: packet[5:6],
		}
		commonHeader.DestConnID = packet[6 : 6+int(commonHeader.DestConnIDLength[0])]
		// packetを縮める
		packet = packet[6+int(commonHeader.DestConnIDLength[0]):]

		// SourceID Connection Lengthが0なら
		if bytes.Equal(packet[0:1], []byte{0x00}) {
			commonHeader.SourceConnIDLength = packet[0:1]
			// packetを縮める
			packet = packet[1:]
		} else {
			commonHeader.SourceConnIDLength = packet[0:1]
			commonHeader.SourceConnID = packet[:1+int(commonHeader.SourceConnID[0])]
			// packetを縮める
			packet = packet[1+int(commonHeader.SourceConnID[0]):]
		}

		// 共通ヘッダの処理はここまで
		// ここからInitialパケットの処理
		var initPacket InitialPacket

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

		rawpacket = QuicRawPacket{
			QuicHeader: commonHeader,
			QuicFrames: []interface{}{initPacket},
		}

	case "10":
		fmt.Println("Handshake Packet")
	}

	return rawpacket
}

// ヘッダ保護を解除したパケットにする
func QuicPacketToUnprotect(commonHeader QuicLongCommonHeader, initpacket InitialPacket, packet []byte, keyblock QuicKeyBlock) []byte {
	// https://tex2e.github.io/blog/protocol/quic-initial-packet-decrypt
	// 5.4.2. ヘッダー保護のサンプル
	pnOffset := 7 + len(commonHeader.DestConnID) + len(commonHeader.SourceConnID) + len(initpacket.Length)
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

	// 保護されているヘッダの最下位4bitを解除する
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

func QuicHeaderToProtect(header, sample, hp []byte) []byte {
	block, err := aes.NewCipher(hp)
	if err != nil {
		log.Fatalf("ヘッダ保護エラー : %v\n", err)
	}
	mask := make([]byte, len(sample))
	block.Encrypt(mask, sample)

	// ヘッダの最初のバイトを保護
	header[0] ^= mask[0] & 0x0f

	a := header[18:22]
	b := mask[1:5]
	for i, _ := range a {
		a[i] ^= b[i]
	}
	// パケット番号をセットして保護する
	for i, _ := range a {
		header[18+i] = a[i]
	}
	return header
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

func EncryptQuicPayload(packetNumber, header, payload []byte, keyblock QuicKeyBlock) []byte {
	// パケット番号で12byteのnonceにする
	packetnum := extendArrByZero(packetNumber, len(keyblock.ClientIV))
	// clientivとxorする
	for i, _ := range packetnum {
		packetnum[i] ^= keyblock.ClientIV[i]
	}
	// AES-128-GCMで暗号化する
	block, _ := aes.NewCipher(keyblock.ClientKey)
	aesgcm, _ := cipher.NewGCM(block)
	encryptedMessage := aesgcm.Seal(nil, packetnum, payload, header)

	return encryptedMessage
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

func NewInitialPacket() QuicRawPacket {
	//var packet []byte
	//
	//infostr := finfo.HeaderForm
	//infostr += finfo.FixedBit
	//infostr += finfo.PacketType
	//infostr += finfo.Reserved
	//infostr += finfo.PacketNumberLegnth
	//
	//header0, _ := strconv.ParseUint(infostr, 2, 8)

	commonHeader := QuicLongCommonHeader{
		FrameByte:          []byte{0xc3},
		Version:            []byte{0x00, 0x00, 0x00, 0x01},
		DestConnIDLength:   []byte{0x08},
		DestConnID:         strtoByte("8394C8F03E515708"),
		SourceConnIDLength: []byte{0x00},
	}

	return QuicRawPacket{
		QuicHeader: commonHeader,
		QuicFrames: []interface{}{
			InitialPacket{
				TokenLength:  []byte{0x00},
				PacketNumber: []byte{0x00, 0x00, 0x00, 0x02},
			},
		},
	}
}

// RFC9000 A.1. サンプル可変長整数デコード
func DecodeVariableInt(plength []int) []byte {
	v := plength[0]
	prefix := v >> 6
	length := 1 << prefix

	v = v & 0x3f
	for i := 0; i < length-1; i++ {
		v = (v << 8) + plength[1]
	}
	//fmt.Printf("%x %d\n", v, v)
	return UintTo2byte(uint16(v))
}

// RFC9000 16. 可変長整数エンコーディング
// 2byteのエンコードしか実装してない
func EncodeVariableInt(length int) []byte {
	var enc uint64
	s := fmt.Sprintf("%b", length)
	if length <= 16383 {
		var zero string
		//0-16383は14bitなので足りないbitは0で埋める
		padding := 14 - len(s)
		for i := 0; i < padding; i++ {
			zero += "0"
		}
		// 2MSBは01で始める
		enc, _ = strconv.ParseUint(fmt.Sprintf("01%s%s", zero, s), 2, 16)
	}
	return UintTo2byte(uint16(enc))
}
