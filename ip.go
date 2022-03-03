package main

// https://www.infraexpert.com/study/tcpip1.html
type IPHeader struct {
	VersionAndHeaderLenght []byte
	ServiceType            []byte
	TotalPacketLength      []byte
	PacketIdentification   []byte
	Flags                  []byte
	TTL                    []byte
	Protocol               []byte
	HeaderCheckSum         []byte
	SourceIPAddr           []byte
	DstIPAddr              []byte
}

func (IPHeader) Create() IPHeader {

	ip := IPHeader{
		VersionAndHeaderLenght: []byte{0x45},
		ServiceType:            []byte{0x00},
		TotalPacketLength:      []byte{0x00, 0x54},
		PacketIdentification:   []byte{0x33, 0xa2},
		Flags:                  []byte{0x40, 0x00},
		TTL:                    []byte{0x40},
		Protocol:               []byte{0x01},
		HeaderCheckSum:         []byte{0x00, 0x00},
		SourceIPAddr:           []byte{0xc0, 0xa8, 0x00, 0x06},
		//DstIPAddr:              []byte{0x01, 0x01, 0x01, 0x01},
		DstIPAddr: []byte{0xc0, 0xa8, 0x00, 0x0f},
	}
	return ip
}
