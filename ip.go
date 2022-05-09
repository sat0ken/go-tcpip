package tcpip

// https://www.infraexpert.com/study/tcpip1.html
type IPHeader struct {
	VersionAndHeaderLength []byte
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

func NewIPHeader(sourceIp, dstIp []byte, protocol string) IPHeader {

	ip := IPHeader{
		VersionAndHeaderLength: []byte{0x45},
		ServiceType:            []byte{0x00},
		TotalPacketLength:      []byte{0x00, 0x00},
		PacketIdentification:   []byte{0x00, 0x00},
		Flags:                  []byte{0x40, 0x00},
		TTL:                    []byte{0x40},
		HeaderCheckSum:         []byte{0x00, 0x00},
		SourceIPAddr:           sourceIp,
		DstIPAddr:              dstIp,
	}

	switch protocol {
	case "IP":
		ip.Protocol = []byte{0x01}
	case "UDP":
		ip.Protocol = []byte{0x11}
	case "TCP":
		ip.Protocol = []byte{0x06}
	}

	return ip
}
