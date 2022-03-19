package main

func main() {
	localip := "127.0.0.1"
	var port uint16 = 8080

	syn := TCPIP{
		DestIP:   localip,
		DestPort: port,
		TcpFlag:  "SYN",
	}
	ThreewayHandShake(syn)
}
