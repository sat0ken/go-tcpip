package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"log"
	"syscall"

	"tcpip"
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

	sock := tcpip.NewSockStreemSocket()
	addr := tcpip.SetSockAddrInet4(tcpip.Iptobyte(LOCALIP), LOCALPORT)
	err := syscall.Connect(sock, &addr)
	if err != nil {
		log.Fatalf("connect err : %v\n", err)
	}

	var hello tcpip.ClientHello
	// ClientHelloメッセージを作成

	tlsinfo, hellobyte := hello.NewClientHello(tcpip.TLS1_3, false, tcpip.UintTo2byte(tls.TLS_CHACHA20_POLY1305_SHA256))
	// メッセージを送信
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
	serverhello := tcpip.ParseTLSHandshake(packet[5:length], tcpip.TLS1_3).(tcpip.ServerHello)
	serverkeyshare := serverhello.TLSExtensions[1].Value.(map[string]interface{})["KeyExchange"]

	// Serverhelloをmessageに入れておく
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, packet[5:length]...)
	tlsinfo.State = tcpip.ContentTypeHandShake

	fmt.Printf("server key share is %x\n", serverkeyshare.([]byte))
	//クライアントの秘密鍵とサーバの公開鍵で共通鍵を生成する
	sharedkey, _ := curve25519.X25519(tlsinfo.ECDHEKeys.PrivateKey, serverkeyshare.([]byte))
	fmt.Printf("sharedkey is %x\n", sharedkey)

	tlsinfo.KeyBlockTLS13 = tcpip.KeyscheduleToMasterSecret(sharedkey, tlsinfo.Handshakemessages)

	copy(packet, packet[length:])

	// read ChangeCipherSpec
	changecipherspec := packet[0:6]
	fmt.Printf("read ChangeCipherSpec is %x, これから暗号化するんやでー\n", changecipherspec)
	copy(packet, packet[6:])

	hanshake := bytes.Split(packet, []byte{0x17, 0x03, 0x03})
	var pubkey *rsa.PublicKey
exit_loop:
	for _, v := range hanshake {
		if len(v) != 0 {
			v = append([]byte{0x17, 0x03, 0x03}, v...)
			length := binary.BigEndian.Uint16(v[3:5]) + 5

			plaintext := tcpip.DecryptChacha20(v[0:length], tlsinfo)
			i := tcpip.ParseTLSHandshake(plaintext[0:len(plaintext)-1], tcpip.TLS1_3)

			switch proto := i.(type) {
			case tcpip.ServerCertificate:
				pubkey = proto.Certificates[0].PublicKey.(*rsa.PublicKey)
			case tcpip.CertificateVerify:
				tcpip.VerifyServerCertificate(pubkey, proto.Signature, tlsinfo.Handshakemessages)
			case tcpip.FinishedMessage:
				key := tlsinfo.KeyBlockTLS13.ServerFinishedKey
				mac := hmac.New(sha256.New, key)
				mac.Write(tcpip.WriteHash((tlsinfo.Handshakemessages)))
				verifydata := mac.Sum(nil)
				if bytes.Equal(verifydata, plaintext[4:len(plaintext)-1]) {
					fmt.Println("Server Verify data is correct !!")
					tlsinfo.ServerHandshakeSeq++
					tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, plaintext[0:len(plaintext)-1]...)
					break exit_loop
				} else {
					// 4.4.4. Finished 本当はdecrypt_errorを送る必要があるのでほんとはだめ
					log.Fatalf("Server Verify data is incorrect! Handshake is stop!")
				}
			}

			tlsinfo.ServerHandshakeSeq++
			tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, plaintext[0:len(plaintext)-1]...)

		}
	}

	// App用のキーを作る
	tlsinfo = tcpip.KeyscheduleToAppTraffic(tlsinfo)

	// ChangeCipherSpecメッセージを作る
	changeCipher := tcpip.NewChangeCipherSpec()

	key := tlsinfo.KeyBlockTLS13.ClientFinishedKey
	mac := hmac.New(sha256.New, key)
	mac.Write(tcpip.WriteHash(tlsinfo.Handshakemessages))
	verifydata := mac.Sum(nil)

	finMessage := []byte{tcpip.HandshakeTypeFinished}
	finMessage = append(finMessage, tcpip.UintTo3byte(uint32(len(verifydata)))...)
	finMessage = append(finMessage, verifydata...)
	finMessage = append(finMessage, tcpip.ContentTypeHandShake)

	fmt.Printf("fin message %x\n", finMessage)

	encryptFinMessage := tcpip.EncryptChacha20(finMessage, tlsinfo)
	fmt.Printf("fin message %x\n", encryptFinMessage)

	var all []byte
	all = append(all, changeCipher...)
	all = append(all, encryptFinMessage...)

	// Finished messageを送る
	syscall.Write(sock, all)
	fmt.Println("send finished message")

	tlsinfo.State = tcpip.ContentTypeApplicationData
	//appData := []byte("hello\n")
	// HTTPリクエストを作成する
	req := tcpip.NewHttpGetRequest("/", fmt.Sprintf("%s:%d", LOCALIP, LOCALPORT))
	appData := req.ReqtoByteArr(req)
	appData = append(appData, tcpip.ContentTypeApplicationData)
	encAppData := tcpip.EncryptChacha20(appData, tlsinfo)

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
		plaintext := tcpip.DecryptChacha20(recvBuf[0:length+5], tlsinfo)
		// Alert(Close notify)が来たらbreakして終了
		if bytes.Equal(plaintext[len(plaintext)-1:], []byte{tcpip.ContentTypeAlert}) {
			break
		} else if bytes.Equal(plaintext[len(plaintext)-1:], []byte{tcpip.ContentTypeApplicationData}) {
			fmt.Printf("\nplaintext is %s\n", string(plaintext[0:len(plaintext)-1]))
			//break
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
