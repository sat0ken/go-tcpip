package main

import (
	"fmt"
	"log"
)

func sendArpICMP(destip string) {

	localif, err := getLocalIpAddr("wlp4s0")
	if err != nil {
		log.Fatalf("getLocalIpAddr err : %v", err)
	}

	// ARPのパケットを作る
	var arp Arp
	arp = NewArpRequest(localif, destip)

	var sendArp []byte
	// Ethernetのパケットを作る
	sendArp = append(sendArp, toByteArr(NewEthernet([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, localif.LocalMacAddr, "ARP"))...)
	sendArp = append(sendArp, toByteArr(arp)...)

	// ARPを送る
	arpreply := arp.Send(localif.Index, sendArp)
	fmt.Printf("ARP Reply : %s\n", printByteArr(arpreply.SenderMacAddr))

	var sendIcmp []byte
	// ICMPパケットを作る
	icmpPacket := NewICMP()
	// IPヘッダを作る
	header := NewIPHeader(localif.LocalIpAddr, iptobyte(destip), "IP")
	// IPヘッダの長さとICMPパケットの長さの合計をIPヘッダのLengthにセットする
	header.TotalPacketLength = uintTo2byte(toByteLen(header) + toByteLen(icmpPacket))

	// チェックサムを計算する
	ipsum := sumByteArr(toByteArr(header))
	header.HeaderCheckSum = checksum(ipsum)

	// Ethernet, IPヘッダ, ICMPパケットの順序でbyteデータにする
	sendIcmp = append(sendIcmp, toByteArr(NewEthernet(arpreply.SenderMacAddr, localif.LocalMacAddr, "IPv4"))...)
	sendIcmp = append(sendIcmp, toByteArr(header)...)
	sendIcmp = append(sendIcmp, toByteArr(icmpPacket)...)

	// ICMPパケットを送る
	icmpreply := icmpPacket.Send(localif.Index, sendIcmp)
	if icmpreply.Type[0] == 0 {
		fmt.Printf("ICMP Reply is %d, OK!\n", icmpreply.Type[0])
	}
}
