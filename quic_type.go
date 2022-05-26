package tcpip

const (
	QuicFrameTypeCrypto = 0x06
)

type QuicKeyBlock struct {
	ClientKey              []byte
	ClientIV               []byte
	ClientHeaderProtection []byte
	ServerKey              []byte
	ServerIV               []byte
	ServerHeaderProtection []byte
}

type FrameInfo struct {
	HeaderForm         string
	FixedBit           string
	PacketType         string
	Reserved           string
	PacketNumberLegnth string
}

type InitialPacket struct {
	FrameInfo          FrameInfo
	Version            []byte
	DestConnIDLength   []byte
	DestConnID         []byte
	SourceConnIDLength []byte
	SourceConnID       []byte
	TokenLength        []byte
	Token              []byte
	Length             []byte
	PacketNumber       []byte
	Payload            []byte
}

type QuicCryptoFrame struct {
	Type   []byte
	Offset []byte
	Length []byte
	Data   []byte
}
