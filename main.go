package main

import (
	"fmt"
	"log"
)

func main() {

	localif, err := getLocalIpAddr("wlp4s0")
	if err != nil {
		log.Fatalf("getLocalIpAddr err : %v", err)
	}

	var ethernet EthernetFrame
	var arp Arp
	arpPacket := arp.Request(localif)

	var sendArp []byte
	sendArp = append(sendArp, toByteArr(ethernet.Create([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, localif.LocalMacAddr, "ARP"))...)
	sendArp = append(sendArp, toByteArr(arpPacket)...)

	arpreply := arp.Send(localif.Index, sendArp)
	fmt.Printf("ARP Reply : %+v\n", arpreply)

	var icmp ICMP
	var ip IPHeader
	var sendIcmp []byte

	icmpPacket := icmp.Create()
	header := ip.Create(localif.LocalIpAddr)
	header.TotalPacketLength = uintTo2byte(toByteLen(header) + toByteLen(icmpPacket))

	sendIcmp = append(sendIcmp, toByteArr(ethernet.Create(arpreply.SenderMacAddr, localif.LocalMacAddr, "IPv4"))...)
	sendIcmp = append(sendIcmp, toByteArr(header)...)
	sendIcmp = append(sendIcmp, toByteArr(icmpPacket)...)

	icmpreply := icmp.Send(localif.Index, sendIcmp)
	fmt.Printf("ICMP Reply : %+v\n", icmpreply)
}
