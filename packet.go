package main

type RawPacket struct {
	ethPacket EthernetFrame
	ipPacket  IPHeader
	tcpPaket  TCPHeader
}

func parseEth(packet []byte) EthernetFrame {
	return EthernetFrame{
		DstMacAddr:    packet[0:6],
		SourceMacAddr: packet[6:12],
		Type:          packet[13:],
	}
}

func parseIP(packet []byte) IPHeader {
	return IPHeader{
		VersionAndHeaderLenght: packet[0:1],
		ServiceType:            packet[1:2],
		TotalPacketLength:      packet[2:4],
		PacketIdentification:   packet[4:6],
		Flags:                  packet[6:8],
		TTL:                    packet[8:9],
		Protocol:               packet[9:10],
		HeaderCheckSum:         packet[10:12],
		SourceIPAddr:           packet[12:16],
		DstIPAddr:              packet[16:],
	}
}

func parseTCP(packet []byte) TCPHeader {

	tcp := TCPHeader{
		SourcePort:       packet[0:2],
		DestPort:         packet[2:4],
		SequenceNumber:   packet[4:8],
		AcknowlegeNumber: packet[8:12],
		HeaderLength:     []byte{packet[12]},
		ControlFlags:     []byte{packet[13]},
		WindowSize:       packet[14:16],
		Checksum:         packet[16:18],
		UrgentPointer:    packet[18:20],
	}
	header_length := (packet[12] >> 4) * 4
	tcp.TCPData = packet[header_length:]

	return tcp
}

func parsePacket(packet []byte) RawPacket {
	eth := parseEth(packet[0:14])
	ip := parseIP(packet[14:34])
	tcp := parseTCP(packet[34:])

	return RawPacket{
		ethPacket: eth,
		ipPacket:  ip,
		tcpPaket:  tcp,
	}
}

func NewPacket(tcpip TCPIP) []byte {
	localif, _ := getLocalIpAddr("wlp4s0")

	localmac := localif.LocalMacAddr
	nginxmac := []byte{0x02, 0x42, 0xac, 0x11, 0x00, 0x02}
	var ethernet EthernetFrame
	ethernet = NewEthernet(localmac, nginxmac, "IPv4")

	localIP := iptobyte(tcpip.DestIP)
	var ipheader IPHeader
	ipheader = NewIPHeader(localIP, localIP, "TCP")

	var tcpheader TCPHeader
	tcpheader = NewTCPHeader(uintTo2byte(42279), uintTo2byte(tcpip.DestPort), tcpip.TcpFlag)

	if tcpip.TcpFlag == "ACK" || tcpip.TcpFlag == "PSHACK" || tcpip.TcpFlag == "FINACK" {
		tcpheader.SequenceNumber = tcpip.SeqNumber
		tcpheader.AcknowlegeNumber = tcpip.AckNumber
	} else if tcpip.TcpFlag == "SYN" {
		tcpheader.SequenceNumber = createSequenceNumber()
	}

	// IP=20byte + tcpヘッダの長さ + tcpオプションの長さ + dataの長さ
	if tcpip.TcpFlag == "PSHACK" {
		ipheader.TotalPacketLength = uintTo2byte(20 + toByteLen(tcpheader) + uint16(len(tcpip.Data)))
	} else {
		ipheader.TotalPacketLength = uintTo2byte(20 + toByteLen(tcpheader)) // + toByteLen(tcpOption))
	}
	ipsum := sumByteArr(toByteArr(ipheader))
	ipheader.HeaderCheckSum = checksum(ipsum)

	num := toByteLen(tcpheader) //+ toByteLen(tcpOption)
	tcpheader.HeaderLength = []byte{byte(num << 2)}

	var dummy TCPDummyHeader
	if tcpip.TcpFlag == "PSHACK" {
		dummy = NewTCPDummyHeader(ipheader, num+uint16(len(tcpip.Data)))
	} else {
		dummy = NewTCPDummyHeader(ipheader, num)
	}

	//ダミーヘッダとTCPヘッダとTCPデータのbyte値を合計してチェックサムを計算する
	sum := sumByteArr(toByteArr(dummy))
	sum += sumByteArr(toByteArr(tcpheader))
	if tcpip.TcpFlag == "PSHACK" {
		// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
		// TCPデータの長さが奇数の場合は、最後に1byteの「0」を補って計算する
		if len(tcpip.Data)%2 != 0 {
			checksumData := tcpip.Data
			checksumData = append(checksumData, byte(0x00))
			sum += sumByteArr(checksumData)
		} else {
			sum += sumByteArr(tcpip.Data)
		}
	}
	tcpheader.Checksum = checksum(sum)

	var rawPacket []byte
	rawPacket = append(rawPacket, toByteArr(ethernet)...)
	rawPacket = append(rawPacket, toByteArr(ipheader)...)
	rawPacket = append(rawPacket, toByteArr(tcpheader)...)
	if tcpip.TcpFlag == "PSHACK" {
		rawPacket = append(rawPacket, tcpip.Data...)
	}

	return rawPacket

}
