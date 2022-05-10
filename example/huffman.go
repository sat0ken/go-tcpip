package main

import (
	"fmt"
	"tcpip"
)

func main() {
	//decode("DELETE")
	//encode("101111111000001100111110000011011111100000")
	//decode("1000011011101")

	fmt.Println(tcpip.HuffmanEncode("10"))
	fmt.Println(tcpip.HuffmanDecode("1000011011101"))
}
