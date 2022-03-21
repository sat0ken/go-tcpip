package main

var IPv4 = []byte{0x08, 0x00}
var ARP = []byte{0x08, 0x06}

type EthernetFrame struct {
	DstMacAddr    []byte
	SourceMacAddr []byte
	Type          []byte
}

func NewEthernet(dstMacAddr, sourceMacAddr []byte, ethType string) EthernetFrame {
	ethernet := EthernetFrame{
		//宛先のMac Addressをセット
		DstMacAddr: dstMacAddr,
		//PCのMac Addressをセット
		SourceMacAddr: sourceMacAddr,
	}
	// https://www.infraexpert.com/study/ethernet4.html
	switch ethType {
	case "IPv4":
		// 0800 = IPv4
		ethernet.Type = IPv4
	case "ARP":
		// 0806 = ARP
		ethernet.Type = ARP
	}
	return ethernet
}
