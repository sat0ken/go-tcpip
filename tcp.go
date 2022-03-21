package main

import (
	"encoding/binary"
	"time"
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

type TCPOpstions struct {
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

func (*TCPHeader) Create(sourceport, destport []byte, tcpflag string) TCPHeader {
	var tcpflagByte byte

	switch tcpflag {
	case "SYN":
		tcpflagByte = 0x02
	case "ACK":
		tcpflagByte = 0x10
	case "PSHACK":
		tcpflagByte = 0x18
	case "FINACK":
		tcpflagByte = 0x11
	}

	return TCPHeader{
		SourcePort:       sourceport,
		DestPort:         destport,
		SequenceNumber:   []byte{0x00, 0x00, 0x00, 0x00},
		AcknowlegeNumber: []byte{0x00, 0x00, 0x00, 0x00},
		HeaderLength:     []byte{0x00},
		ControlFlags:     []byte{tcpflagByte},
		// WindowSize = とりま適当な値を入れてる,
		WindowSize:    []byte{0x16, 0xd0},
		Checksum:      []byte{0x00, 0x00},
		UrgentPointer: []byte{0x00, 0x00},
	}
}
func (*TCPDummyHeader) Create(header IPHeader, length uint16) TCPDummyHeader {
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
func (*TCPOpstions) Create() TCPOpstions {
	tcpoption := TCPOpstions{
		// オプション番号2, Length, 値(2byte)
		//MaxsSegmentSize: []byte{0x02, 0x04, 0xff, 0xd7},
		MaxsSegmentSize: []byte{0x02, 0x04, 0x00, 0x30},
		// オプション番号4, Length + EndOfList
		SackPermitted: []byte{0x04, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		// オプション番号1
		//NoOperation: []byte{0x01},
		// オプション番号3, Length, 値(1byte)
		//WindowScale: []byte{0x03, 0x03, 0x07},
		// オプション番号8, Length, Timestamp value(4byte), echo reply(4byte)
		//Timestamps: []byte{0x08, 0x0a},
	}

	// Timestamp value(4byte)を追加
	//tcpoption.Timestamps = append(tcpoption.Timestamps, createTCPTimestamp()...)
	//tcpoption.Timestamps = append(tcpoption.Timestamps, []byte{0x80, 0x6a, 0x9b, 0xca}...)
	// echo reply(4byte)を追加
	//tcpoption.Timestamps = append(tcpoption.Timestamps, []byte{0x00, 0x00, 0x00, 0x00}...)

	return tcpoption
}

func parseTCP(packet []byte) TCPHeader {

	tcp := TCPHeader{
		SourcePort:       packet[0:2],
		DestPort:         packet[2:4],
		SequenceNumber:   packet[4:8],
		AcknowlegeNumber: packet[8:12],
		HeaderLength:     []byte{packet[12]},
		ControlFlags:     []byte{packet[13]},
		WindowSize:       packet[14:16],
		Checksum:         packet[16:18],
		UrgentPointer:    packet[18:20],
	}
	header_length := (packet[12] >> 4) * 4
	tcp.TCPData = packet[header_length:]

	return tcp
}
