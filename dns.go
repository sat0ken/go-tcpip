package main

type DNS struct {
	TransactionID []byte
	Flags         []byte
	Questions     []byte
	Answers       []byte
	Authority     []byte
	Additional    []byte
	Queries       struct {
		Name  []byte
		Type  []byte
		Class []byte
	}
}

func NewDNSQuery(host string) DNS {
	return DNS{
		// 適当な値をセット
		TransactionID: []byte{0x15, 0x78},
		// https://atmarkit.itmedia.co.jp/ait/articles/1601/29/news014.html
		// Flags 1byte: QR = 0, OPCode = 0000, AA = 0, TC = 0, RD = 1 → 0x01
		// Flags 2byte: RA = 0, Z = 0, AD = 1, CD = 0, RCode = 0000   → 100000 = 32 = 0x20
		Flags:      []byte{0x01, 0x20},
		Questions:  []byte{0x00, 0x01},
		Answers:    []byte{0x00, 0x00},
		Authority:  []byte{0x00, 0x00},
		Additional: []byte{0x00, 0x01},
		Queries: struct {
			Name  []byte
			Type  []byte
			Class []byte
		}{
			Name:  []byte(host),
			Type:  []byte{0x00, 0x01},
			Class: []byte{0x00, 0x01},
		},
	}

}
