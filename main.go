package main

import (
	"fmt"
	"log"
	"syscall"
)

func main() {
	//ICMPを作成
	var icmp ICMP
	icmpPacket := icmp.Create()
	icmpsum := sumByteArr(toByteArr(icmpPacket))
	icmpPacket.CheckSum = calcChecksum(icmpsum)

	// IPヘッダを作成
	var ip IPHeader
	header := ip.Create()
	sum := sumByteArr(toByteArr(header))
	header.HeaderCheckSum = calcChecksum(sum)

	// TotalLengthをセット
	header.TotalPacketLength = uintTo2byte(toByteLen(header) + toByteLen(icmpPacket))

	var ethernet EthernetFrame
	var sendbyte []byte
	sendbyte = append(sendbyte, toByteArr(ethernet.Create())...)
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

	//conn, err := net.Dial("ip4:icmp", "1.1.1.1")
	//if err != nil {
	//	log.Fatalf("net dial err : %s", err)
	//}
	//_, err = conn.Write(sendbyte)
	//if err != nil {
	//	log.Fatalf("write err : %s", err)
	//}

	//addr := syscall.SockaddrInet4{
	//	Port: 0,
	//	Addr: [4]byte{1, 1, 1, 1},
	//}
	addr := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_ARP,
		Ifindex:  3,
		Hatype:   syscall.ARPHRD_ETHER,
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		log.Fatalf("fd err : %v\n", err)
	}
	err = syscall.Sendto(fd, sendbyte, 0, &addr)
	if err != nil {
		log.Fatalf("Send to err : %v\n", err)
	}
}
