package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"log"
	"syscall"
)

// おまじない
// sudo sh -c 'echo 3 > /proc/sys/net/ipv4/tcp_retries2'
// sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

const (
	LOCALIP   = "127.0.0.1"
	LOCALPORT = 8443
	// github.com
	GITHUBIP   = "13.114.40.48"
	GITHUBPORT = 443
)

func main() {
	//clientCert := readClientCertificate()

	sock := NewSockStreemSocket()
	addr := setSockAddrInet4(iptobyte(LOCALIP), LOCALPORT)
	err := syscall.Connect(sock, &addr)
	if err != nil {
		log.Fatalf("connect err : %v\n", err)
	}

	var hello ClientHello
	tlsinfo, hellobyte := hello.NewClientHello(TLS1_3)
	syscall.Write(sock, hellobyte)

	var packet []byte
	// ServerHello, ChangeCipherSpec, EncryptedExtensions, Certificate, CertificateVerify, Finishedを受信する
	for {
		recvBuf := make([]byte, 2000)
		n, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		packet = recvBuf[0:n]
		break
	}

	// read ServerHello
	length := binary.BigEndian.Uint16(packet[3:5]) + 5
	serverhello := parseTLSHandshake(packet[5:length], "1.3").(ServerHello)
	serverkeyshare := serverhello.TLSExtensions[1].Value.(map[string]interface{})["KeyExchange"]

	// Serverhelloをmessageに入れておく
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, packet[5:length]...)
	tlsinfo.State = ContentTypeHandShake

	var msinfo MasterSecretInfo
	msinfo.PreMasterSecret = serverkeyshare.([]byte)
	msinfo.ServerRandom = serverhello.Random
	msinfo.ClientRandom = noRandomByte(32)

	fmt.Printf("server key share is %x\n", serverkeyshare.([]byte))
	fmt.Printf("privateKey is %x\n", tlsinfo.ECDHEKeys.privateKey)
	sharedkey, _ := curve25519.X25519(tlsinfo.ECDHEKeys.privateKey, serverkeyshare.([]byte))
	fmt.Printf("sharedkey is %x\n", sharedkey)

	tlsinfo.KeyBlockTLS13 = keyscheduleToMasterSecret(sharedkey, tlsinfo.Handshakemessages)

	copy(packet, packet[length:])

	// read ChangeCipherSpec
	changecipherspec := packet[0:6]
	fmt.Printf("read ChangeCipherSpec is %x, これから暗号化するんやでー\n", changecipherspec)
	copy(packet, packet[6:])

	hanshake := bytes.Split(packet, []byte{0x17, 0x03, 0x03})

	var pubkey *rsa.PublicKey
	for _, v := range hanshake {
		if len(v) != 0 {
			v = append([]byte{0x17, 0x03, 0x03}, v...)
			length := binary.BigEndian.Uint16(v[3:5]) + 5

			plaintext := decryptChacha20(v[0:length], tlsinfo)
			//tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, plaintext[0:len(plaintext)-1]...)
			i := parseTLSHandshake(plaintext[0:len(plaintext)-1], "1.3")

			switch proto := i.(type) {
			case ServerCertificate:
				pubkey = proto.Certificates[0].PublicKey.(*rsa.PublicKey)
			case CertificateVerify:
				verifyServerCertificate(pubkey, proto.Signature, tlsinfo.Handshakemessages)
			}

			tlsinfo.ServerHandshakeSeq++
			tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, plaintext[0:len(plaintext)-1]...)

			// Finishedまで来たらforを抜ける
			if bytes.Equal(plaintext[0:1], []byte{HandshakeTypeFinished}) {
				break
			}
		}
	}

	// App用のキーを作る
	tlsinfo = keyscheduleToAppTraffic(tlsinfo)

	// ChangeCipherSpecメッセージを作る
	changeCipher := NewChangeCipherSpec()

	key := tlsinfo.KeyBlockTLS13.clientFinishedKey
	mac := hmac.New(sha256.New, key)
	mac.Write(writeHash(tlsinfo.Handshakemessages))
	verifydata := mac.Sum(nil)

	finMessage := []byte{HandshakeTypeFinished}
	finMessage = append(finMessage, uintTo3byte(uint32(len(verifydata)))...)
	finMessage = append(finMessage, verifydata...)
	finMessage = append(finMessage, ContentTypeHandShake)

	fmt.Printf("fin message %x\n", finMessage)

	encryptFinMessage := encryptChacha20(finMessage, tlsinfo)
	fmt.Printf("fin message %x\n", encryptFinMessage)

	var all []byte
	all = append(all, changeCipher...)
	all = append(all, encryptFinMessage...)

	// Finished messageを送る
	syscall.Write(sock, all)
	fmt.Println("send finished message")

	tlsinfo.State = ContentTypeApplicationData
	//appData := []byte("hello\n")
	// HTTPリクエストを作成する
	req := NewHttpGetRequest("/", fmt.Sprintf("%s:%d", LOCALIP, LOCALPORT))
	appData := req.reqtoByteArr(req)
	appData = append(appData, ContentTypeApplicationData)
	encAppData := encryptChacha20(appData, tlsinfo)

	// HTTPSリクエストを送る
	syscall.Write(sock, encAppData)
	tlsinfo.ClientAppSeq++

	fmt.Println("send Application data")
	for {
		recvBuf := make([]byte, 2000)
		_, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		length := binary.BigEndian.Uint16(recvBuf[3:5])
		plaintext := decryptChacha20(recvBuf[0:length+5], tlsinfo)
		// Alert(Close notify)が来たらbreakして終了
		if bytes.Equal(plaintext[len(plaintext)-1:], []byte{ContentTypeAlert}) {
			break
		} else if bytes.Equal(plaintext[len(plaintext)-1:], []byte{ContentTypeApplicationData}) {
			fmt.Printf("\nplaintext is %s\n", string(plaintext[0:len(plaintext)-1]))
		}
		tlsinfo.ServerAppSeq++
	}

	//closeNotify := encryptChacha20(strtoByte("010015"), tlsinfo)
	//// Close notifyで接続終了する
	//syscall.Write(sock, closeNotify)
	//fmt.Println("send close notify")
	//for {
	//	recvBuf := make([]byte, 2000)
	//	n, _, err := syscall.Recvfrom(sock, recvBuf, 0)
	//	if err != nil {
	//		log.Fatalf("read err : %v", err)
	//	}
	//	fmt.Printf("%x\n", recvBuf[0:n])
	//	break
	//}

}
