package main

import (
	"log"
	"syscall"
)

// htons converts a short (uint16) from host-to-network byte order.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// https://www.n-study.com/tcp-ip/arp-format/
type Arp struct {
	HardwareType  []byte
	ProtocolType  []byte
	HardwareSize  []byte
	ProtocolSize  []byte
	Opcode        []byte
	SenderMacAddr []byte
	SenderIpAddr  []byte
	TargetMacAddr []byte
	TargetIpAddr  []byte
}

func NewArpRequest(localif LocalIpMacAddr, targetip string) Arp {
	return Arp{
		// イーサネットの場合、0x0001で固定
		HardwareType: []byte{0x00, 0x01},
		// IPv4の場合、0x0800で固定
		ProtocolType: []byte{0x08, 0x00},
		// MACアドレスのサイズ(バイト)。0x06
		HardwareSize: []byte{0x06},
		// IPアドレスのサイズ(バイト)。0x04
		ProtocolSize: []byte{0x04},
		// ARPリクエスト:0x0001
		Opcode: []byte{0x00, 0x01},
		// 送信元MACアドレス
		SenderMacAddr: localif.LocalMacAddr,
		// 送信元IPアドレス
		SenderIpAddr: localif.LocalIpAddr,
		// ターゲットMACアドレス broadcastなのでAll zero
		TargetMacAddr: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		// ターゲットIPアドレス
		TargetIpAddr: iptobyte(targetip),
	}
}

func (*Arp) Send(ifindex int, packet []byte) Arp {
	addr := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_ARP,
		Ifindex:  ifindex,
		Hatype:   syscall.ARPHRD_ETHER,
	}
	sendfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("create sendfd err : %v\n", err)
	}
	defer syscall.Close(sendfd)

	err = syscall.Sendto(sendfd, packet, 0, &addr)
	if err != nil {
		log.Fatalf("Send to err : %v\n", err)
	}

	for {
		recvBuf := make([]byte, 80)
		_, _, err := syscall.Recvfrom(sendfd, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// EthernetのTypeがArpがチェック
		if recvBuf[12] == 0x08 && recvBuf[13] == 0x06 {
			// ArpのOpcodeがReplyかチェック
			if recvBuf[20] == 0x00 && recvBuf[21] == 0x02 {
				return parseArpPacket(recvBuf[14:])
			}
		}
	}
}

func parseArpPacket(packet []byte) Arp {
	return Arp{
		HardwareType:  []byte{packet[0], packet[1]},
		ProtocolType:  []byte{packet[2], packet[3]},
		HardwareSize:  []byte{packet[4]},
		ProtocolSize:  []byte{packet[5]},
		Opcode:        []byte{packet[6], packet[7]},
		SenderMacAddr: []byte{packet[8], packet[9], packet[10], packet[11], packet[12], packet[13]},
		SenderIpAddr:  []byte{packet[14], packet[15], packet[16], packet[17]},
		TargetMacAddr: []byte{packet[18], packet[19], packet[20], packet[21], packet[22], packet[23]},
		TargetIpAddr:  []byte{packet[24], packet[25], packet[26], packet[27]},
	}
}
