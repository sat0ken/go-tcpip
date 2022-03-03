package main

type EthernetFrame struct {
	DstMacAddr    []byte
	SourceMacAddr []byte
	Type          []byte
}

func (EthernetFrame) Create() EthernetFrame {
	ethernet := EthernetFrame{
		//ルータのMac Addressをセット
		//DstMacAddr: []byte{0x1c, 0x3b, 0xf3, 0x95, 0x6a, 0x2c},
		DstMacAddr: []byte{0xb8, 0x27, 0xeb, 0xa7, 0xb3, 0xe7},
		//PCのMac Addressをセット
		SourceMacAddr: []byte{0xe4, 0xa7, 0xa0, 0x86, 0xf1, 0x19},
		// https://www.infraexpert.com/study/ethernet4.html
		// 0800 = IPv4
		Type: []byte{0x08, 0x00},
	}
	return ethernet
}
