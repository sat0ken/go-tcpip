package main

import (
	"fmt"
	"log"
)

func ping() {
	ipAddr, err := getLocalIpAddr("wlp4s0")
	if err != nil {
		log.Fatalf("getLocalIpAddr err : %v", err)
	}

	//ICMPを作成
	var icmp ICMP
	icmpPacket := icmp.Create()
	icmpsum := sumByteArr(toByteArr(icmpPacket))
	icmpPacket.CheckSum = calcChecksum(icmpsum)

	// IPヘッダを作成
	var ip IPHeader
	header := ip.Create(ipAddr.LocalIpAddr)
	sum := sumByteArr(toByteArr(header))
	header.HeaderCheckSum = calcChecksum(sum)

	// TotalLengthをセット
	header.TotalPacketLength = uintTo2byte(toByteLen(header) + toByteLen(icmpPacket))

	//var ethernet EthernetFrame
	var sendbyte []byte
	//sendbyte = append(sendbyte, toByteArr(ethernet.Create(ipAddr.LocalMacAddr))...)
	sendbyte = append(sendbyte, toByteArr(header)...)
	sendbyte = append(sendbyte, toByteArr(icmpPacket)...)

	fmt.Printf("TotalLEngth : %d\n", header.TotalPacketLength)

	fmt.Println("---check ip header---")
	checktoByteArr(header)
	fmt.Println("---check icmp packet---")
	checktoByteArr(icmpPacket)
	for _, v := range sendbyte {
		fmt.Printf("%x ", v)
	}
	fmt.Println()
}
