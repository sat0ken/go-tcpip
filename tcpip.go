package main

import (
	"strconv"
	"strings"
)

type TCPIP struct {
	DestIP    string
	DestPort  uint16
	TcpFlag   string
	SeqNumber []byte
	AckNumber []byte
}

func iptobyte(ip string) []byte {
	var ipbyte []byte
	for _, v := range strings.Split(ip, ".") {
		i, _ := strconv.ParseUint(v, 10, 8)
		ipbyte = append(ipbyte, byte(i))
	}
	return ipbyte
}

func NewTCPIP(tcpip TCPIP) []byte {
	localIP := iptobyte(tcpip.DestIP)

	var ipheader IPHeader
	ipheader = ipheader.Create(localIP, localIP, "TCP")

	var tcpheader TCPHeader
	// 送信先ポート8080=1f90
	// 自分のポートは42279でとりま固定
	tcpheader = tcpheader.Create(uintTo2byte(42279), uintTo2byte(tcpip.DestPort), tcpip.TcpFlag)
	if tcpip.TcpFlag == "ACK" {
		tcpheader.SequenceNumber = tcpip.SeqNumber
		tcpheader.AcknowlegeNumber = tcpip.AckNumber
	}

	// IP=20byte + tcpヘッダの長さ + tcpオプションの長さ
	ipheader.TotalPacketLength = uintTo2byte(20 + toByteLen(tcpheader)) // + toByteLen(tcpOption))

	num := toByteLen(tcpheader) //+ toByteLen(tcpOption)
	tcpheader.HeaderLength = []byte{byte(num << 2)}

	var dummy TCPDummyHeader
	dummy = dummy.Create(ipheader, num)

	//ダミーヘッダとTCPヘッダのbyte値を合計してチェックサムを計算する
	sum := sumByteArr(toByteArr(dummy))
	sum += sumByteArr(toByteArr(tcpheader))
	//sum += sumByteArr(toByteArr(tcpOption))
	tcpheader.Checksum = checksum(sum)

	var tcpipPacket []byte
	tcpipPacket = append(tcpipPacket, toByteArr(ipheader)...)
	tcpipPacket = append(tcpipPacket, toByteArr(tcpheader)...)

	return tcpipPacket
}
