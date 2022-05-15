package tcpip

import (
	"fmt"
	"strconv"
	"strings"
)

var bitLength = []int{5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 19}

var HuffmanCodeTable = map[string]string{
	" ":   "010100",
	"!":   "1111111000",
	"\"":  "1111111001",
	"#":   "111111111010",
	"$":   "1111111111001",
	"%":   "010101",
	"&":   "11111000",
	"\\'": "11111111010",
	"(":   "1111111010",
	")":   "1111111011",
	"*":   "11111001",
	"+":   "11111111011",
	",":   "11111010",
	"-":   "010110",
	".":   "010111",
	"/":   "011000",
	"0":   "00000",
	"1":   "00001",
	"2":   "00010",
	"3":   "011001",
	"4":   "011010",
	"5":   "011011",
	"6":   "011100",
	"7":   "011101",
	"8":   "011110",
	"9":   "011111",
	":":   "1011100",
	";":   "11111011",
	"<":   "111111111111100",
	"=":   "100000",
	">":   "111111111011",
	"?":   "1111111100",
	"@":   "1111111111010",
	"A":   "100001",
	"B":   "1011101",
	"C":   "1011110",
	"D":   "1011111",
	"E":   "1100000",
	"F":   "1100001",
	"G":   "1100010",
	"H":   "1100011",
	"I":   "1100100",
	"J":   "1100101",
	"K":   "1100110",
	"L":   "1100111",
	"M":   "1101000",
	"N":   "1101001",
	"O":   "1101010",
	"P":   "1101011",
	"Q":   "1101100",
	"R":   "1101101",
	"S":   "1101110",
	"T":   "1101111",
	"U":   "1110000",
	"V":   "1110001",
	"W":   "1110010",
	"X":   "11111100",
	"Y":   "1110011",
	"Z":   "11111101",
	"[":   "1111111111011",
	"\\":  "1111111111111110000",
	"]":   "1111111111100",
	"^":   "11111111111100",
	"_":   "100010",
	"`":   "111111111111101",
	"a":   "00011",
	"b":   "100011",
	"c":   "00100",
	"d":   "100100",
	"e":   "00101",
	"f":   "100101",
	"g":   "100110",
	"h":   "100111",
	"i":   "00110",
	"j":   "1110100",
	"k":   "1110101",
	"l":   "101000",
	"m":   "101001",
	"n":   "101010",
	"o":   "00111",
	"p":   "101011",
	"q":   "1110110",
	"r":   "101100",
	"s":   "01000",
	"t":   "01001",
	"u":   "101101",
	"v":   "1110111",
	"w":   "1111000",
	"x":   "1111001",
	"y":   "1111010",
	"z":   "1111011",
	"{":   "111111111111110",
	"|":   "11111111100",
	"}":   "11111111111101",
	"~":   "1111111111101",
}

// 詳解HTTP/2の8章のPerlのコードを元に実装
// https://github.com/tunetheweb/http2-in-action/blob/main/Listing%208.1/hpack_huffman_encoding.pl
func HuffmanEncode(str string) []byte {
	split := strings.Split(str, "")

	var encstr string
	// 1文字ずつに分解した文字をハフマン符号化テーブルを参照して検索
	// 検索してヒットした結果のバイナリ文字列を変数に追加
	for _, v := range split {
		encstr += HuffmanCodeTable[v]
	}
	// バイナリ文字列をパディングして8、オクテットで割り切れるようにする
	// 割り切れなかったら末尾に1を入れて埋める
	for {
		if len(encstr)%8 != 0 {
			encstr += "1"
		} else {
			break
		}
	}

	//バイナリ化した文字列の長さを計算
	//binLength, _ := strconv.ParseUint(fmt.Sprintf("%x", (127+(len(decstr)/8))/2), 10, 16)

	var result string
	for i, _ := range encstr {
		// 各4bit値を繰り返し処理して、16進数に変換
		if i%4 == 0 {
			bin, _ := strconv.ParseUint(encstr[i:i+4], 2, 4)
			result += fmt.Sprintf("%x", bin)
		}
	}

	return strtoByte(result)
}

func HuffmanDecode(hpackBytes []byte) string {
	var binstr string
	// bitフォーマットのstringにする
	for _, v := range hpackBytes {
		binstr += fmt.Sprintf("%08b", v)
	}

	var decstr string
	for {
		for _, v := range bitLength {
			// 残り文字数より多いbitはskipする
			if len(binstr) < v {
				continue
			}
			result := getHuffmanTable(binstr[0:v])
			if result != "" {
				binstr = binstr[v:]
				decstr += result
				//fmt.Printf("remain str is %s, length is %d\n", encstr, len(encstr))
			}
		}
		if len(binstr) == 0 {
			break
		} else if !strings.Contains(binstr, "0") {
			// 残りの文字が全部１なら全部Paddingだからbreak
			break
		}
	}
	return decstr
}

func getHuffmanTable(str string) (hit string) {
	for k, v := range HuffmanCodeTable {
		if v == str {
			hit = k
		}
	}
	return hit
}

func DecodeHttp2Header(headerByte []byte) []Http2Header {

	var http2Header []Http2Header

	for i := 0; i < len(headerByte); i++ {
		binstr := fmt.Sprintf("%08b", headerByte[i])
		//fmt.Printf("i is %d, binstr is %s\n", i, binstr)
		if strings.HasPrefix(binstr, "1") {
			// インデックスヘッダフィールド表現(1で始まる)
			// 残り7bitを10進数にする
			d, _ := strconv.ParseInt(binstr[1:], 2, 8)
			http2Header = append(http2Header, StaticHttp2Table[d-1])
		} else if strings.HasPrefix(binstr, "01") {
			var header Http2Header
			// インデックス更新を伴うリテラルヘッダフィールド（01で始まる）
			// Httpヘッダ名をIndex番号で取得
			d, _ := strconv.ParseInt(binstr[2:], 2, 8)
			header.Name = StaticHttp2Table[d-1].Name

			//　Valueの値を2進数にする
			binstr = fmt.Sprintf("%08b", headerByte[i+1])
			if binstr[0:1] == "1" {
				d, _ := strconv.ParseInt(binstr[1:], 2, 8)
				header.Value = HuffmanDecode(headerByte[i+2 : i+2+int(d)])
				http2Header = append(http2Header, header)
				// 次のヘッダが始まる位置にiを進める
				i = i + 1 + int(d)
			}
		} else if binstr == "00000000" {

			binstr = fmt.Sprintf("%08b", headerByte[i+1])
			if binstr[0:1] == "1" {
				// Name Stringを処理する
				d, _ := strconv.ParseInt(binstr[1:], 2, 8)
				nameString := HuffmanDecode(headerByte[i+2 : i+2+int(d)])
				// Name Valueを処理する
				i = i + 2 + int(d)
				binstr = fmt.Sprintf("%08b", headerByte[i])
				d, _ = strconv.ParseInt(binstr[1:], 2, 8)
				nameValue := HuffmanDecode(headerByte[i+1 : i+1+int(d)])

				// incrementする
				i += int(d)

				http2Header = append(http2Header, Http2Header{
					Name:  nameString,
					Value: nameValue,
				})

			}
		}
	}

	return http2Header
}

func getHttp2HeaderIndexByValue(value string) (index int) {
	for k, v := range StaticHttp2Table {
		if v.Value == value {
			index = k
		}
	}
	return index
}

func getHttp2HeaderIndexByName(name string) (index int) {
	for k, v := range StaticHttp2Table {
		if v.Name == name {
			index = k
		}
	}
	return index
}

func CreateHttp2Header(name, value string) (headerByte []byte) {

	if name == "" {
		// インデックスヘッダフィールド表現(1で始まる)
		index := getHttp2HeaderIndexByValue(value)
		headerIndex, _ := strconv.ParseUint(fmt.Sprintf("1%07b", index+1), 2, 8)
		headerByte = append(headerByte, byte(headerIndex))
	} else {
		// インデックス更新を伴うリテラルヘッダフィールド（01で始まる）
		index := getHttp2HeaderIndexByName(name)
		headerIndex, _ := strconv.ParseUint(fmt.Sprintf("01%06b", index+1), 2, 8)

		// Huffman codignを意味する1のbitとcodingされたLengthを意味する7bit
		encodeVal := HuffmanEncode(value)
		headerVal, _ := strconv.ParseUint(fmt.Sprintf("1%07b", len(encodeVal)), 2, 8)

		headerByte = append(headerByte, byte(headerIndex))
		headerByte = append(headerByte, byte(headerVal))
		headerByte = append(headerByte, encodeVal...)

	}

	return headerByte
}
