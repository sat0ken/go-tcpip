package tcpip

const (
	QuicFrameTypeCrypto = 0x06
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

type QuicKeyBlock struct {
	ClientKey              []byte
	ClientIV               []byte
	ClientHeaderProtection []byte
	ServerKey              []byte
	ServerIV               []byte
	ServerHeaderProtection []byte
}

type QuicRawPacket struct {
	QuicHeader interface{}
	QuicFrames []interface{}
}

type QuicLongCommonHeader struct {
	FrameByte          []byte
	Version            []byte
	DestConnIDLength   []byte
	DestConnID         []byte
	SourceConnIDLength []byte
	SourceConnID       []byte
}

type QuicFrame struct {
	FrameInfo FrameInfo
	Packet    interface{}
}

type FrameInfo struct {
	HeaderForm         string
	FixedBit           string
	PacketType         string
	Reserved           string
	PacketNumberLegnth string
}

type InitialPacket struct {
	//CommonHeader QuicLongCommonHeader
	TokenLength  []byte
	Token        []byte
	Length       []byte
	PacketNumber []byte
	Payload      []byte
}

type QuicCryptoFrame struct {
	Type   []byte
	Offset []byte
	Length []byte
	Data   []byte
}
