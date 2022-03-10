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

func (IPHeader) Create(sourceIp, dstIp []byte, protocol string) IPHeader {

	ip := IPHeader{
		VersionAndHeaderLenght: []byte{0x45},
		ServiceType:            []byte{0x00},
		//TotalPacketLength:      []byte{0x00, 0x54},
		TotalPacketLength:    []byte{0x00, 0x00},
		PacketIdentification: []byte{0x33, 0xa2},
		Flags:                []byte{0x40, 0x00},
		TTL:                  []byte{0x40},
		HeaderCheckSum:       []byte{0x00, 0x00},
		SourceIPAddr:         sourceIp,
		//SourceIPAddr:           []byte{0xc0, 0xa8, 0x00, 0x06},
		//DstIPAddr:              []byte{0xc0, 0xa8, 0x00, 0x0f},
		DstIPAddr: dstIp,
	}

	switch protocol {
	case "IP":
		ip.Protocol = []byte{0x01}
	case "UDP":
		ip.Protocol = []byte{0x11}
	case "TCP":
		ip.Protocol = []byte{0x06}
	}

	//checksumを計算するために合計する
	sum := sumByteArr(toByteArr(ip))
	//合計値からchecksumを計算してHeaderにセットしてreturnする
	ip.HeaderCheckSum = calcChecksum(sum)
	return ip
}
