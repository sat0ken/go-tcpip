package main

import (
	"bufio"
	"math/rand"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type LocalIpMacAddr struct {
	LocalMacAddr []byte
	LocalIpAddr  []byte
	Index        int
}

// ローカルのmacアドレスとIPを返す
func getLocalIpAddr(ifname string) (localif LocalIpMacAddr, err error) {
	nif, err := net.InterfaceByName(ifname)
	if err != nil {
		return localif, err
	}
	localif.LocalMacAddr = nif.HardwareAddr
	localif.Index = nif.Index

	addrs, err := nif.Addrs()
	if err != nil {
		return localif, err
	}
	for _, addr := range addrs {
		//if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.To4() != nil {
				localif.LocalIpAddr = ipnet.IP.To4()
			}
		}
	}

	return localif, nil
}

// TLSのClientHelloで32byteの乱数をセット
func random32byte() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

// クライアント側で利用可能な暗号スイートのリストを返す
// 読み込んでいるファイルの内容は openssl ciphers -V | grep v1.2 の出力結果を保存したもの
func getChipersList() []byte {
	data, _ := os.Open("tls1_2_ciphers.txt")
	defer data.Close()

	var b []byte

	r := regexp.MustCompile(`0x[0-9A-F][0-9A-F]`)
	scanner := bufio.NewScanner(data)
	for scanner.Scan() {
		match := r.FindAllString(scanner.Text(), -1)
		byte1, _ := strconv.ParseUint(strings.Replace(match[0], "0x", "", -1), 16, 8)
		byte2, _ := strconv.ParseUint(strings.Replace(match[1], "0x", "", -1), 16, 8)
		b = append(b, byte(byte1))
		b = append(b, byte(byte2))
	}
	return b
}
