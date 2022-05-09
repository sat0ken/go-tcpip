package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

func tls13_keyschedule() {

	// private key (32 octets): 49 af 42 ba 7f 79 94 85 2d 71 3e f2 78 4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05
	clientPrivateKey, _ := hex.DecodeString("49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005")
	// public key (32 octets): c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f
	serverPublickKey, _ := hex.DecodeString("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")

	// {client} construct a ClientHello handshake message:
	clienthello := "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"
	// {server} construct a ServerHello handshake message:
	sererhello := "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304"

	clientserverhello, _ := hex.DecodeString(clienthello + sererhello)

	sharedkey, _ := curve25519.X25519(clientPrivateKey, serverPublickKey)
	tcpip.KeyscheduleToMasterSecret(sharedkey, clientserverhello)
}

func main() {

	sock := tcpip.NewSockStreemSocket()
	addr := tcpip.SetSockAddrInet4(tcpip.Iptobyte(LOCALIP), LOCALPORT)
	err := syscall.Connect(sock, &addr)
	if err != nil {
		log.Fatalf("connect err : %v\n", err)
	}

	var hello tcpip.ClientHello
	// ClientHelloメッセージを作成
	tlsinfo, hellobyte := hello.NewClientHello(tcpip.TLS1_3)
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
