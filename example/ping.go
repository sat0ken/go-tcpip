package main

import (
	"fmt"
	"log"
	"tcpip"
)

func main() {

	destip := "192.168.0.15"

	localif, err := tcpip.GetLocalInterface("wlp3s0")
	if err != nil {
		log.Fatalf("getLocalIpAddr err : %v", err)
	}

	// ARPのパケットを作る
	var arp tcpip.Arp
	arp = tcpip.NewArpRequest(localif, destip)

	var sendArp []byte
	// Ethernetのパケットを作る
	sendArp = append(sendArp, tcpip.ToPacket(tcpip.NewEthernet([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, localif.LocalMacAddr, "ARP"))...)
	sendArp = append(sendArp, tcpip.ToPacket(arp)...)

	// ARPを送る
	arpreply := arp.Send(localif.Index, sendArp)
	fmt.Printf("ARP Reply : %x\n", arpreply.SenderMacAddr)

	var sendIcmp []byte
	// ICMPパケットを作る
	icmpPacket := tcpip.NewICMP()
	// IPヘッダを作る
	header := tcpip.NewIPHeader(localif.LocalIpAddr, tcpip.Iptobyte(destip), "IP")
	// IPヘッダの長さとICMPパケットの長さの合計をIPヘッダのLengthにセットする
	totalLength := len(tcpip.ToPacket(header)) + len(tcpip.ToPacket(icmpPacket))
	header.TotalPacketLength = tcpip.UintTo2byte(uint16(totalLength))

	// チェックサムを計算する
	ipsum := tcpip.SumbyteArr(tcpip.ToPacket(header))
	header.HeaderCheckSum = tcpip.CalcChecksum(ipsum)

	// Ethernet, IPヘッダ, ICMPパケットの順序でbyteデータにする
	sendIcmp = append(sendIcmp, tcpip.ToPacket(tcpip.NewEthernet(arpreply.SenderMacAddr, localif.LocalMacAddr, "IPv4"))...)
	sendIcmp = append(sendIcmp, tcpip.ToPacket(header)...)
	sendIcmp = append(sendIcmp, tcpip.ToPacket(icmpPacket)...)

	// ICMPパケットを送る
	icmpreply := icmpPacket.Send(localif.Index, sendIcmp)
	if icmpreply.Type[0] == 0 {
		fmt.Printf("ICMP Reply is %d, OK!\n", icmpreply.Type[0])
	}
}
