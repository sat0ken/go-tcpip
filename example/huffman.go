package main

import (
	"fmt"
	"tcpip"
)

func main() {

	//fmt.Println(tcpip.HuffmanEncode("DELETE"))
	fmt.Println(tcpip.HuffmanDecode([]byte{0xbf, 0x83, 0x3e, 0x0d, 0xf8, 0x3f}))
	//
	//var b []byte
	//b = hpack.AppendHuffmanString(nil, "DELETE")
	//fmt.Printf("%x\n", b)
	//s, _ := hpack.HuffmanDecodeToString([]byte{0xbf, 0x83, 0x3e, 0x0d, 0xf8, 0x3f})
	//fmt.Printf("%s\n", s)
}
