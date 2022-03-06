package main

import (
	"net"
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
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				localif.LocalIpAddr = ipnet.IP.To4()
			}
		}
	}

	return localif, nil
}
