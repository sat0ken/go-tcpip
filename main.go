package main

import (
	"fmt"
	"log"
)

func main() {
	localmac := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	localif, err := getLocalIpAddr("lo")
	if err != nil {
		log.Fatalf("getLocalIpAddr err : %v", err)
	}
	fmt.Printf("%+v\n", localif)
	var ip IPHeader
	ipheader := ip.Create(localif.LocalIpAddr, localif.LocalIpAddr, "UDP")

	var udp UDPHeader
	udppacket := udp.Create([]byte{0xa6, 0xe9}, []byte{0x30, 0x39})
	udpdata := []byte(`hogehoge`)

	ipheader.TotalPacketLength = uintTo2byte(uint16(20) + toByteLen(udppacket) + uint16(len(udpdata)))
	udppacket.PacketLenth = uintTo2byte(toByteLen(udppacket) + uint16(len(udpdata)))

	var dummy DummyHeader
	dummyHeader := dummy.Create(ipheader)
	dummyHeader.PacketLenth = udp.PacketLenth

	sum := sumByteArr(toByteArr(dummy))
	sum += sumByteArr(toByteArr(udppacket))
	sum += sumByteArr(udpdata)

	udppacket.Checksum = calcChecksum(sum)

	var eth EthernetFrame
	var packet []byte
	packet = append(packet, toByteArr(eth.Create(localmac, localmac, "IPv4"))...)
	packet = append(packet, toByteArr(ipheader)...)
	packet = append(packet, toByteArr(udppacket)...)
	packet = append(packet, udpdata...)

	printByteArr(packet)
	udp.Send(packet)
}
