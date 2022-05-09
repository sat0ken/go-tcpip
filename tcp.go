package tcpip

import (
	"encoding/binary"
	"time"
)

const (
	SYN    = 0x02
	ACK    = 0x10
	SYNACK = 0x12
	PSHACK = 0x18
	FINACK = 0x11
)

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
	TCPData          []byte
}

type TCPOptions struct {
	MaxsSegmentSize []byte
	SackPermitted   []byte
	Timestamps      []byte
	NoOperation     []byte
	WindowScale     []byte
}

type TCPDummyHeader struct {
	SourceIPAddr []byte
	DstIPAddr    []byte
	Protocol     []byte
	Length       []byte
}

func NewTCPHeader(sourceport, destport []byte, tcpflag string) TCPHeader {
	var tcpflagByte byte

	switch tcpflag {
	case "SYN":
		tcpflagByte = SYN
	case "ACK":
		tcpflagByte = ACK
	case "PSHACK":
		tcpflagByte = PSHACK
	case "FINACK":
		tcpflagByte = FINACK
	}

	return TCPHeader{
		SourcePort:       sourceport,
		DestPort:         destport,
		SequenceNumber:   []byte{0x00, 0x00, 0x00, 0x00},
		AcknowlegeNumber: []byte{0x00, 0x00, 0x00, 0x00},
		HeaderLength:     []byte{0x00},
		ControlFlags:     []byte{tcpflagByte},
		// WindowSize = とりま適当な値を入れてる
		//WindowSize:    []byte{0x16, 0xd0},
		WindowSize:    []byte{0xfa, 0xf0},
		Checksum:      []byte{0x00, 0x00},
		UrgentPointer: []byte{0x00, 0x00},
	}
}

func NewTCPDummyHeader(header IPHeader, length uint16) TCPDummyHeader {
	return TCPDummyHeader{
		SourceIPAddr: header.SourceIPAddr,
		DstIPAddr:    header.DstIPAddr,
		Protocol:     []byte{0x00, 0x06},
		Length:       []byte{0x00, byte(length)},
	}
}

func createTCPTimestamp() []byte {
	t := time.Now()
	t.AddDate(1, 1, 1)

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(t.Unix()))

	return b
}

// https://milestone-of-se.nesuke.com/nw-basic/tcp-udp/tcp-option/
func NewTCPOptions() TCPOptions {
	tcpoption := TCPOptions{
		// オプション番号2, Length, 値(2byte)
		// size: 1460 bytes
		MaxsSegmentSize: []byte{0x02, 0x04, 0x05, 0xb4},
		// オプション番号4, Length
		SackPermitted: []byte{0x04, 0x02},
		// オプション番号1
		NoOperation: []byte{0x01},
		// オプション番号3, Length, 値(1byte)
		WindowScale: []byte{0x03, 0x03, 0x07},
		// オプション番号8, Length, Timestamp value(4byte), echo reply(4byte)
		Timestamps: []byte{0x08, 0x0a},
	}

	// Timestamp value(4byte)を追加
	tcpoption.Timestamps = append(tcpoption.Timestamps, createTCPTimestamp()...)
	// echo reply(4byte)を追加
	tcpoption.Timestamps = append(tcpoption.Timestamps, []byte{0x00, 0x00, 0x00, 0x00}...)

	return tcpoption
}
