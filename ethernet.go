package main

type EthernetFrame struct {
	DstMacAddr    []byte
	SourceMacAddr []byte
	Type          []byte
}

func (*EthernetFrame) Create(dstMacAddr, sourceMacAddr []byte, ethType string) EthernetFrame {
	ethernet := EthernetFrame{
		//ルータのMac Addressをセット
		DstMacAddr: dstMacAddr,
		//PCのMac Addressをセット
		SourceMacAddr: sourceMacAddr,
	}
	// https://www.infraexpert.com/study/ethernet4.html
	switch ethType {
	case "IPv4":
		// 0800 = IPv4
		ethernet.Type = []byte{0x08, 0x00}
	case "ARP":
		// 0806 = ARP
		ethernet.Type = []byte{0x08, 0x06}
	}
	return ethernet
}
