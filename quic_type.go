package tcpip

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
