package main

import (
	"fmt"
	"strconv"
	"strings"
	"tcpip"
)

func decode(str string) {
	split := strings.Split(str, "")

	var decstr string
	// 1文字ずつに分解した文字をハフマン符号化テーブルを参照して検索
	// 検索してヒットした結果のバイナリ文字列を変数に追加
	for _, v := range split {
		decstr += tcpip.HuffmanCodeTable[v]
	}
	fmt.Printf("length is %d, %s\n", len(decstr), decstr)
	// バイナリ文字列をパディングして8、オクテットで割り切れるようにする
	// 割り切れなかったら末尾に1を入れて埋める
	for {
		if len(decstr)%8 != 0 {
			decstr += "1"
		} else {
			break
		}
	}

	//binLength := strconv.FormatInt(int64((127+(len(decstr)/8))/2), 16)
	binLength, _ := strconv.ParseUint(fmt.Sprintf("%x", (127+(len(decstr)/8))/2), 10, 16)

	//fmt.Printf("Huffman Encoding Flag + Length: %x\n", binLength)
	//fmt.Println(binLength)

	var result string
	for i, _ := range decstr {
		if i%4 == 0 {
			bin, _ := strconv.ParseUint(decstr[i:i+4], 2, 4)
			result += fmt.Sprintf("%x", bin)
		}
	}

	fmt.Println(result)
	encode(decstr[:binLength])

}

func getHuffmanTable(str string) (hit string) {
	for k, v := range tcpip.HuffmanCodeTable {
		if v == str {
			//fmt.Printf("key is %s, value is %s\n", k, v)
			hit = k
		}
	}
	return hit
}

var lenInBits = []int{5, 6, 7, 8}

func encode(encstr string) {

	for {
		result := getHuffmanTable(encstr[0:7])
		if result != "" {
			fmt.Println(result)
			encstr = encstr[7:]
		}

		if len(encstr) == 0 {
			break
		}
	}
}

func main() {
	//decode("DELETE")
	encode("101111111000001100111110000011011111100000")
}
