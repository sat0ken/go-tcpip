package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"syscall"
	"time"

	"tcpip"
)

// TLS1.2ハンドシェイク+クライアント認証
func main() {
	clientCert := tcpip.ReadClientCertificate()

	sock := tcpip.NewSockStreemSocket()
	addr := tcpip.SetSockAddrInet4(tcpip.Iptobyte(LOCALIP), LOCALPORT)
	err := syscall.Connect(sock, &addr)
	if err != nil {
		log.Fatalf("connect err : %v\n", err)
	}

	var tlsinfo tcpip.TLSInfo
	var hello tcpip.ClientHello
	var hellobyte []byte
	tlsinfo, hellobyte = hello.NewClientHello(tcpip.TLS1_2, false, tcpip.UintTo2byte(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))
	syscall.Write(sock, hellobyte)

	fmt.Printf("client random : %x\n", tlsinfo.MasterSecretInfo.ClientRandom)

	// handshakeメッセージはverify_data作成のために保存しておく
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, hellobyte[5:]...)

	var tlsproto []tcpip.TLSProtocol
	var tlsbyte []byte

	for {
		recvBuf := make([]byte, 1500)
		_, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// ServerHello, Certificates, ServerHelloDoneをパース
		tlsproto, tlsbyte = tcpip.ParseTLSPacket(recvBuf)
		break
	}

	// parseしたServerHello, Certificates, ServerHelloDoneをappend
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, tlsbyte...)

	var pubkey *rsa.PublicKey
	for _, v := range tlsproto {
		switch proto := v.HandshakeProtocol.(type) {
		case tcpip.ServerHello:
			// ServerHelloからrandomを取り出す
			tlsinfo.MasterSecretInfo.ServerRandom = proto.Random
		case tcpip.ServerCertificate:
			_, ok := proto.Certificates[0].PublicKey.(*rsa.PublicKey)
			if !ok {
				log.Fatalf("cast pubkey err : %v\n", ok)
			}
			// Certificateからサーバの公開鍵を取り出す
			pubkey = proto.Certificates[0].PublicKey.(*rsa.PublicKey)
		case tcpip.ServerKeyExchange:
			if proto.ECDiffieHellmanServerParams.NamedCurve[1] == tcpip.CurveIDx25519 {
				// サーバの公開鍵でECDHEの鍵交換を行う
				tlsinfo.ECDHEKeys = tcpip.GenrateECDHESharedKey(proto.ECDiffieHellmanServerParams.Pubkey)
				// premaster secretに共通鍵をセット
				tlsinfo.MasterSecretInfo.PreMasterSecret = tlsinfo.ECDHEKeys.SharedKey
			}
		}
	}
	_ = pubkey
	fmt.Printf("ClientRandom : %x\n", tlsinfo.MasterSecretInfo.ClientRandom)
	fmt.Printf("ServerRandom : %x\n", tlsinfo.MasterSecretInfo.ServerRandom)

	//certificateメッセージを作る
	var clientCertMessage tcpip.ClientCertificate
	clientCertMessageBytes := clientCertMessage.NewClientCertificate(clientCert)
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, clientCertMessageBytes[5:]...)

	// ClientKeyExchangeメッセージを作る
	// premaster secretをサーバの公開鍵で暗号化する
	// 暗号化したらTLSのMessage形式にしてClientKeyExchangeを作る
	var clientKeyExchange tcpip.ClientKeyExchange
	var clientKeyExchangeBytes []byte
	// RSA鍵交換のとき
	//clientKeyExchangeBytes, tlsinfo.MasterSecretInfo.PreMasterSecret = clientKeyExchange.NewClientKeyRSAExchange(pubkey)
	// 生成した公開鍵をClientKeyExchangeにセットする
	clientKeyExchangeBytes = clientKeyExchange.NewClientKeyECDHAExchange(tlsinfo.ECDHEKeys.PublicKey)
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, clientKeyExchangeBytes[5:]...)

	// CertificateVerifyメッセージを作る
	var certVerify tcpip.CertificateVerify
	certVerifyBytes := certVerify.NewCertificateVerify(clientCert, tlsinfo.Handshakemessages)
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, certVerifyBytes[5:]...)

	// ChangeCipherSpecメッセージを作る
	changeCipher := tcpip.NewChangeCipherSpec()

	// 鍵を作る
	tlsinfo.MasterSecretInfo.MasterSecret, tlsinfo.KeyBlock = tcpip.CreateMasterandKeyblock(tlsinfo.MasterSecretInfo)

	var verifyData []byte
	verifyData = tcpip.CreateVerifyData(tlsinfo.MasterSecretInfo.MasterSecret, tcpip.CLientFinishedLabel, tlsinfo.Handshakemessages)
	finMessage := []byte{tcpip.HandshakeTypeFinished}
	finMessage = append(finMessage, tcpip.UintTo3byte(uint32(len(verifyData)))...)
	finMessage = append(finMessage, verifyData...)
	fmt.Printf("finMessage : %x\n", finMessage)

	// 送ったClient finishedを入れる、Serverからのfinishedと照合するため
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, finMessage...)

	rheader := tcpip.NewTLSRecordHeader("Handshake", uint16(len(finMessage)))
	encryptFin := tcpip.EncryptClientMessage(rheader, finMessage, tlsinfo)

	// ClientKeyexchange, ChangeCipehrspec, ClientFinsihedを全部まとめる
	var all []byte
	all = append(all, clientCertMessageBytes...)
	all = append(all, clientKeyExchangeBytes...)
	all = append(all, certVerifyBytes...)
	all = append(all, changeCipher...)
	all = append(all, encryptFin...)

	syscall.Write(sock, all)
	for {
		recvBuf := make([]byte, 1500)
		_, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// 0byteがChangeCipherSpecであるか
		if bytes.HasPrefix(recvBuf, []byte{tcpip.HandshakeTypeChangeCipherSpec}) {
			// 6byteからServerFinishedMessageになるのでそれをunpackする
			serverfin := tcpip.DecryptServerMessage(recvBuf[6:51], tlsinfo, tcpip.ContentTypeHandShake)
			verify := tcpip.CreateVerifyData(tlsinfo.MasterSecretInfo.MasterSecret, tcpip.ServerFinishedLabel, tlsinfo.Handshakemessages)

			if bytes.Equal(serverfin[4:], verify) {
				fmt.Printf("server fin : %x, client verify : %x, verify is ok !!\n", serverfin[4:], verify)
			}
		}
		break
	}

	//送って受け取ったらシーケンスを増やす
	tlsinfo.ClientSequenceNum++

	//req := NewHttpGetRequest("/", fmt.Sprintf("%s:%d", LOCALIP, LOCALPORT))
	//reqbyte := req.reqtoByteArr(req)
	//encAppdata := encryptClientMessage(NewTLSRecordHeader("AppDada", uint16(len(reqbyte))), reqbyte, tlsinfo)

	//fmt.Printf("appdata : %x\n", reqbyte)

	appdata := []byte("hello\n")
	encAppdata := tcpip.EncryptClientMessage(tcpip.NewTLSRecordHeader("AppDada", uint16(len(appdata))), appdata, tlsinfo)
	syscall.Write(sock, encAppdata)

	time.Sleep(10 * time.Millisecond)

	for {
		recvBuf := make([]byte, 1500)
		_, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// 0byteがApplication Dataであるか
		if bytes.HasPrefix(recvBuf, []byte{tcpip.ContentTypeApplicationData}) {
			// 6byteからServerFinishedMessageになるのでそれをunpackする
			length := binary.BigEndian.Uint16(recvBuf[3:5])
			serverappdata := tcpip.DecryptServerMessage(recvBuf[0:length+5], tlsinfo, tcpip.ContentTypeApplicationData)
			//fmt.Printf("app data from server : %x\n", appdata)
			fmt.Printf("app data from server : %s\n", string(serverappdata))
		}
		break
	}
	tlsinfo.ClientSequenceNum++

	encryptAlert := tcpip.EncryptClientMessage(tcpip.NewTLSRecordHeader("Alert", 2), []byte{0x01, 0x00}, tlsinfo)
	syscall.Write(sock, encryptAlert)
	time.Sleep(10 * time.Millisecond)
	syscall.Close(sock)
}
