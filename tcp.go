package main

// https://www.infraexpert.com/study/tcpip8.html
type TCPHeader struct {
	SourcePort       []byte
	DestPort         []byte
	SequenceNumber   []byte
	AcknowlegeNumber []byte
	HeaderLength     []byte
	ControlFlags     []byte
	WindowSize       []byte
	Checksum         []byte
	UrgentPointer    []byte
	TCPOptionByte    []byte
}

func (*TCPHeader) CreateSyn(sourceport, destport []byte) TCPHeader {
	return TCPHeader{
		SourcePort:       sourceport,
		DestPort:         destport,
		SequenceNumber:   []byte{0x00, 0x00, 0x00, 0x00},
		AcknowlegeNumber: []byte{0x00, 0x00, 0x00, 0x00},
		HeaderLength:     []byte{0x00},
		ControlFlags:     []byte{0x00},
		WindowSize:       []byte{0xff, 0xff},
		Checksum:         []byte{0x00, 0x00},
		UrgentPointer:    []byte{0x00, 0x00},
	}
}
