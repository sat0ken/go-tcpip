package main

// https://www.infraexpert.com/study/tcpip12.html
type UDPHeader struct {
	SourcePort  []byte
	DestPort    []byte
	PacketLenth []byte
	Checksum    []byte
}

func (*UDPHeader) Create(sourceport, destport []byte) UDPHeader {
	return UDPHeader{
		SourcePort:  sourceport,
		DestPort:    destport,
		PacketLenth: nil,
		Checksum:    nil,
	}
}
