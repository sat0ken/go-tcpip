package tcpip

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"strconv"
	"syscall"
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
		ServerIV:               hkdfExpandLabel(serverInitSecret, quicIVLabel, nil, 12),
		ServerHeaderProtection: hkdfExpandLabel(serverInitSecret, quicHPLabel, nil, 16),
	}
}

// QUICパケットをパースする
func ParseRawQuicPacket(packet []byte, protected bool) (rawpacket QuicRawPacket) {

	p0 := fmt.Sprintf("%08b", packet[0])
	// LongHeader = 1 で始まる
	// ShortHeader = 0 で始まる
	switch p0[2:4] {
	// Initial Packet
	case "00":
		commonHeader := QuicLongCommonHeader{
			HeaderByte:       packet[0:1],
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
			commonHeader.SourceConnID = packet[1 : 1+int(commonHeader.SourceConnIDLength[0])]
			// packetを縮める
			packet = packet[1+int(commonHeader.SourceConnIDLength[0]):]
		}
		//fmt.Printf("packet is %x\n", packet)

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

		// Length~を処理
		if protected {
			initPacket.Length = packet[0:2]
			initPacket.PacketNumber = packet[2:4]
			initPacket.Payload = packet[4:]
			//可変長整数をデコードする
			initPacket.Length = DecodeVariableInt([]int{int(initPacket.Length[0]), int(initPacket.Length[1])})
		} else {
			initPacket.Length = packet[0:2]
			// パケット番号の長さで変える
			if bytes.Equal(commonHeader.HeaderByte, []byte{0xC3}) {
				// 4byteのとき
				initPacket.PacketNumber = packet[2:6]
				initPacket.Payload = packet[6:]
			} else if bytes.Equal(commonHeader.HeaderByte, []byte{0xC1}) {
				// 2byteのとき
				initPacket.PacketNumber = packet[2:4]
				initPacket.Payload = packet[4:]
			} else if bytes.Equal(commonHeader.HeaderByte, []byte{0xC0}) {
				// 1byteのとき
				initPacket.PacketNumber = packet[2:3]
				initPacket.Payload = packet[3:]
			}
		}

		rawpacket = QuicRawPacket{
			QuicHeader: commonHeader,
			QuicFrames: []interface{}{initPacket},
		}

	case "10":
		fmt.Println("Handshake Packet")
	case "11":
		commonHeader := QuicLongCommonHeader{
			HeaderByte: packet[0:1],
			Version:    packet[1:5],
		}
		// Destination Connection Length と ID
		if bytes.Equal(packet[5:6], []byte{0x00}) {
			commonHeader.DestConnID = packet[5:6]
			packet = packet[6:]
		}
		commonHeader.SourceConnIDLength = packet[0:1]
		commonHeader.SourceConnID = packet[:1+int(commonHeader.SourceConnIDLength[0])]
		// packetを縮める
		packet = packet[1+int(commonHeader.SourceConnID[0]):]

		retryPacket := RetryPacket{
			RetryToken:         packet[0 : len(packet)-16],
			RetryIntergrityTag: packet[len(packet)-16:],
		}
		//fmt.Println("Parse Retry Packet, token is %x\n", retryPacket.RetryToken)
		rawpacket = QuicRawPacket{
			QuicHeader: commonHeader,
			QuicFrames: []interface{}{retryPacket},
		}
	}

	return rawpacket
}

// ヘッダ保護を解除したパケットにする
func QuicPacketToUnprotect(commonHeader QuicLongCommonHeader, initpacket InitialPacket, packet, hpkey []byte) []byte {
	// https://tex2e.github.io/blog/protocol/quic-initial-packet-decrypt
	// 5.4.2. ヘッダー保護のサンプル
	pnOffset := 7 + len(commonHeader.DestConnID) + len(commonHeader.SourceConnID) + len(initpacket.Length)
	pnOffset += len(initpacket.Token) + len(initpacket.TokenLength)
	sampleOffset := pnOffset + 4

	fmt.Printf("pnOffset is %d, sampleOffset is %d\n", pnOffset, sampleOffset)
	block, err := aes.NewCipher(hpkey)
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

	// Packet Numberの0byte目がある場所
	pnumStartOffset := len(header) - 4

	a := header[pnumStartOffset : pnumStartOffset+4]
	b := mask[1:5]
	for i, _ := range a {
		a[i] ^= b[i]
	}
	// パケット番号をセットして保護する
	for i, _ := range a {
		header[pnumStartOffset+i] = a[i]
	}
	return header
}

func DecryptQuicPayload(packetNumber, header, payload []byte, keyblock QuicKeyBlock) []byte {
	// パケット番号で8byteのnonceにする
	packetnum := extendArrByZero(packetNumber, 8)

	block, _ := aes.NewCipher(keyblock.ServerKey)
	aesgcm, _ := cipher.NewGCM(block)
	// IVとxorしたのをnonceにする
	nonce := getXORNonce(packetnum, keyblock.ServerIV)
	// 復号する
	plaintext, err := aesgcm.Open(nil, nonce, payload, header)
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
func ParseQuicFrame(packet []byte) (frames interface{}) {
	for i := 0; i < len(packet); i++ {
		switch packet[0] {
		case QuicFrameTypeACK:
			frames = QuicACKFrame{
				Type:                packet[0:1],
				LargestAcknowledged: packet[1:2],
				AckDelay:            packet[2:3],
				AckRangeCount:       packet[3:4],
				FirstAckRange:       packet[4:5],
			}
		case QuicFrameTypeCrypto:
			cframe := QuicCryptoFrame{
				Type:   packet[0:1],
				Offset: packet[1:2],
			}
			decodedLength := sumByteArr(DecodeVariableInt([]int{int(packet[2]), int(packet[3])}))
			cframe.Length = UintTo2byte(uint16(decodedLength))
			cframe.Data = packet[4 : 4+decodedLength]
			frames = cframe
		}
	}
	return frames
}

func NewQuicLongHeader(destConnID, sourceConnID []byte, pnum, pnumlen uint) QuicRawPacket {
	// とりあえず2byte
	var packetNum []byte
	if pnumlen == 2 {
		packetNum = UintTo2byte(uint16(pnum))
	} else if pnumlen == 4 {
		packetNum = UintTo4byte(uint32(pnum))
	}

	// パケット番号長が2byteの場合0xC1になる
	// 先頭の6bitは110000, 下位の2bitがLenghtを表す
	// 1 LongHeader
	//  1 Fixed bit
	//   00 Packet Type
	//     00 Reserved
	// 17.2. Long Header Packets
	// That is, the length of the Packet Number field is the value of this field plus one.
	// 生成するときは1をパケット番号長から引く、2-1は1、2bitの2進数で表すと01
	// 11000001 = 0xC1 となる
	var firstByte byte
	if len(packetNum) == 2 {
		firstByte = 0xC1
	} else if len(packetNum) == 4 {
		firstByte = 0xC3
	}
	// Headerを作る
	commonHeader := QuicLongCommonHeader{
		HeaderByte:         []byte{firstByte},
		Version:            []byte{0x00, 0x00, 0x00, 0x01},
		DestConnIDLength:   []byte{byte(len(destConnID))},
		DestConnID:         destConnID,
		SourceConnIDLength: []byte{byte(len(sourceConnID))},
		SourceConnID:       sourceConnID,
	}

	return QuicRawPacket{
		QuicHeader: commonHeader,
		QuicFrames: []interface{}{
			InitialPacket{
				TokenLength:  []byte{0x00},
				PacketNumber: packetNum,
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

func NewQuicCryptoFrame(data []byte) QuicCryptoFrame {
	return QuicCryptoFrame{
		Type:   []byte{QuicFrameTypeCrypto},
		Offset: []byte{0x00},
		Length: EncodeVariableInt(len(data)),
		Data:   data,
	}
}

func SendQuicPacket(data []byte, udpinfo UDPInfo) QuicRawPacket {
	sendfd := NewClientUDPSocket(udpinfo.ClientPort, udpinfo.ClientAddr)
	server := syscall.SockaddrInet4{
		Port: udpinfo.ServerPort,
		Addr: udpinfo.ServerAddr,
	}
	err := syscall.Sendto(sendfd, data, 0, &server)
	if err != nil {
		log.Fatalf("Can't UDP data to server : %v", err)
	}

	var packet QuicRawPacket
	for {
		recvBuf := make([]byte, 1500)
		n, _, err := syscall.Recvfrom(sendfd, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		fmt.Printf("recv packet : %x\n", recvBuf[0:n])
		packet = ParseRawQuicPacket(recvBuf[0:n], false)
		break
	}
	return packet
}

// paddingフレームを読み飛ばして、QUICのフレームを配列に入れて返す
func SkipPaddingFrame(packet []byte) [][]byte {
	var framesByte [][]byte

	for i := 0; i < len(packet); i++ {
		// ACK
		if packet[i] == 0x02 {
			framesByte = append(framesByte, packet[i:i+5])
			i += 4
		} else if packet[i] == 0x06 { // Crypto Frame
			length := packet[i+2 : i+4]
			// 可変長整数をデコードする
			decodedLength := sumByteArr(DecodeVariableInt([]int{int(length[0]), int(length[1])}))
			//cryptoData := packet[i+4 : i+4+int(decodedLength)]
			framesByte = append(framesByte, packet[i:i+4+int(decodedLength)])
			i += 4 + int(decodedLength)
		}
	}

	return framesByte
}
