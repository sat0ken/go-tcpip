package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"log"
	"syscall"
	"time"
)

func handshake_mtls_1_2() {
	clientCert := readClientCertificate()

	sock := NewSockStreemSocket()
	addr := setSockAddrInet4(iptobyte(LOCALIP), LOCALPORT)
	err := syscall.Connect(sock, &addr)
	if err != nil {
		log.Fatalf("connect err : %v\n", err)
	}

	var tlsinfo TLSInfo
	var hello ClientHello
	var hellobyte []byte
	tlsinfo, hellobyte = hello.NewClientHello(TLS1_2)
	syscall.Write(sock, hellobyte)

	fmt.Printf("client random : %x\n", tlsinfo.MasterSecretInfo.ClientRandom)

	// handshakeメッセージはverify_data作成のために保存しておく
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, hellobyte[5:]...)

	var tlsproto []TLSProtocol
	var tlsbyte []byte

	for {
		recvBuf := make([]byte, 1500)
		_, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// ServerHello, Certificates, ServerHelloDoneをパース
		tlsproto, tlsbyte = parseTLSPacket(recvBuf)
		break
	}

	// parseしたServerHello, Certificates, ServerHelloDoneをappend
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, tlsbyte...)

	var pubkey *rsa.PublicKey
	for _, v := range tlsproto {
		switch proto := v.HandshakeProtocol.(type) {
		case ServerHello:
			// ServerHelloからrandomを取り出す
			tlsinfo.MasterSecretInfo.ServerRandom = proto.Random
		case ServerCertificate:
			_, ok := proto.Certificates[0].PublicKey.(*rsa.PublicKey)
			if !ok {
				log.Fatalf("cast pubkey err : %v\n", ok)
			}
			// Certificateからサーバの公開鍵を取り出す
			pubkey = proto.Certificates[0].PublicKey.(*rsa.PublicKey)
		case ServerKeyExchange:
			if proto.ECDiffieHellmanServerParams.NamedCurve[1] == CurveIDx25519 {
				// サーバの公開鍵でECDHEの鍵交換を行う
				tlsinfo.ECDHEKeys = genrateECDHESharedKey(proto.ECDiffieHellmanServerParams.Pubkey)
				// premaster secretに共通鍵をセット
				tlsinfo.MasterSecretInfo.PreMasterSecret = tlsinfo.ECDHEKeys.sharedKey
			}
		}
	}
	_ = pubkey
	fmt.Printf("ClientRandom : %x\n", tlsinfo.MasterSecretInfo.ClientRandom)
	fmt.Printf("ServerRandom : %x\n", tlsinfo.MasterSecretInfo.ServerRandom)

	//certificateメッセージを作る
	var clientCertMessage ClientCertificate
	clientCertMessageBytes := clientCertMessage.NewClientCertificate(clientCert)
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, clientCertMessageBytes[5:]...)

	// ClientKeyExchangeメッセージを作る
	// premaster secretをサーバの公開鍵で暗号化する
	// 暗号化したらTLSのMessage形式にしてClientKeyExchangeを作る
	var clientKeyExchange ClientKeyExchange
	var clientKeyExchangeBytes []byte
	// RSA鍵交換のとき
	//clientKeyExchangeBytes, tlsinfo.MasterSecretInfo.PreMasterSecret = clientKeyExchange.NewClientKeyRSAExchange(pubkey)
	// 生成した公開鍵をClientKeyExchangeにセットする
	clientKeyExchangeBytes = clientKeyExchange.NewClientKeyECDHAExchange(tlsinfo.ECDHEKeys.publicKey)
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, clientKeyExchangeBytes[5:]...)

	// CertificateVerifyメッセージを作る
	var certVerify CertificateVerify
	certVerifyBytes := certVerify.NewCertificateVerify(clientCert, tlsinfo.Handshakemessages)
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, certVerifyBytes[5:]...)

	// ChangeCipherSpecメッセージを作る
	changeCipher := NewChangeCipherSpec()

	// 鍵を作る
	tlsinfo.MasterSecretInfo.MasterSecret, tlsinfo.KeyBlock = createMasterandKeyblock(tlsinfo.MasterSecretInfo)

	var verifyData []byte
	verifyData = createVerifyData(tlsinfo.MasterSecretInfo.MasterSecret, CLientFinishedLabel, tlsinfo.Handshakemessages)
	finMessage := []byte{HandshakeTypeFinished}
	finMessage = append(finMessage, uintTo3byte(uint32(len(verifyData)))...)
	finMessage = append(finMessage, verifyData...)
	fmt.Printf("finMessage : %x\n", finMessage)

	// 送ったClient finishedを入れる、Serverからのfinishedと照合するため
	tlsinfo.Handshakemessages = append(tlsinfo.Handshakemessages, finMessage...)

	rheader := NewTLSRecordHeader("Handshake", uint16(len(finMessage)))
	encryptFin := encryptClientMessage(rheader, finMessage, tlsinfo)

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
		if bytes.HasPrefix(recvBuf, []byte{HandshakeTypeChangeCipherSpec}) {
			// 6byteからServerFinishedMessageになるのでそれをunpackする
			serverfin := decryptServerMessage(recvBuf[6:51], tlsinfo, ContentTypeHandShake)
			verify := createVerifyData(tlsinfo.MasterSecretInfo.MasterSecret, ServerFinishedLabel, tlsinfo.Handshakemessages)

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
	encAppdata := encryptClientMessage(NewTLSRecordHeader("AppDada", uint16(len(appdata))), appdata, tlsinfo)
	syscall.Write(sock, encAppdata)

	time.Sleep(10 * time.Millisecond)

	for {
		recvBuf := make([]byte, 1500)
		_, _, err := syscall.Recvfrom(sock, recvBuf, 0)
		if err != nil {
			log.Fatalf("read err : %v", err)
		}
		// 0byteがApplication Dataであるか
		if bytes.HasPrefix(recvBuf, []byte{ContentTypeApplicationData}) {
			// 6byteからServerFinishedMessageになるのでそれをunpackする
			length := binary.BigEndian.Uint16(recvBuf[3:5])
			serverappdata := decryptServerMessage(recvBuf[0:length+5], tlsinfo, ContentTypeApplicationData)
			//fmt.Printf("app data from server : %x\n", appdata)
			fmt.Printf("app data from server : %s\n", string(serverappdata))
		}
		break
	}
	tlsinfo.ClientSequenceNum++

	encryptAlert := encryptClientMessage(NewTLSRecordHeader("Alert", 2), []byte{0x01, 0x00}, tlsinfo)
	syscall.Write(sock, encryptAlert)
	time.Sleep(10 * time.Millisecond)
	syscall.Close(sock)
}
