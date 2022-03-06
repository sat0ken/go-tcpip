package main

// https://www.infraexpert.com/study/tcpip8.html
type TCPHeader struct {
	SourcePort       []byte
	DestPort         []byte
	SequenceNumber   []byte
	AcknowlegeNumber []byte
	DataOffset       []byte
	ControlFlags     []byte
	WindowSize       []byte
	Checksum         []byte
	UrgentPointer    []byte
	Options          []byte
}
