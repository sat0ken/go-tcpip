package main

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/curve25519"
)

type zeroSource5 struct{}

func (zeroSource5) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

func randomByte(num int) []byte {
	b := make([]byte, num)
	rand.Read(b)
	return b
}

// https://billatnapier.medium.com/little-protects-you-on-line-like-ecdh-lets-go-create-it-a14188eabded
func main() {
	//pkey_bob, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//pkey_alice, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//
	//pubkey_bob := pkey_bob.PublicKey
	//pubkey_alice := pkey_alice.PublicKey
	//
	//fmt.Println(pubkey_bob.Params())
	//fmt.Println(elliptic.P256().Params())
	//
	//fmt.Printf("bob's Private key is   %x\n", pkey_bob.D)
	//fmt.Printf("alice's Private key is %x\n", pkey_alice.D)
	//
	//fmt.Printf("bob's Public key is   %x%x\n", pkey_bob.X, pkey_bob.Y)
	//fmt.Printf("alice's Public key is %x%x\n", pkey_alice.X, pkey_alice.Y)
	//
	//// AliceはBobの公開鍵で楕円曲線の計算をする
	//a, _ := pubkey_bob.Curve.ScalarMult(pubkey_bob.X, pubkey_bob.Y, pkey_alice.D.Bytes())
	//// BobはAliceの公開鍵で楕円曲線の計算をする
	//b, _ := pubkey_alice.Curve.ScalarMult(pubkey_alice.X, pubkey_alice.Y, pkey_bob.D.Bytes())
	//
	//shared_bob := sha256.Sum256(a.Bytes())
	//shared_alice := sha256.Sum256(b.Bytes())

	//fmt.Printf("bob's Shared key is   %x\n", shared_bob)
	//fmt.Printf("alice's Shared key is   %x\n", shared_alice)

	// aliceとbobが秘密鍵を作る
	alice_privateKey := randomByte(curve25519.ScalarSize)
	bob_privateKey := randomByte(curve25519.ScalarSize)

	// aliceとbobが公開鍵を作る
	alice_publicKey, _ := curve25519.X25519(alice_privateKey, curve25519.Basepoint)
	bob_publicKey, _ := curve25519.X25519(bob_privateKey, curve25519.Basepoint)

	// 楕円曲線暗号のスカラー倍算=楕円曲線上で掛け算をする
	// https://ja.wikipedia.org/wiki/%E6%A5%95%E5%86%86%E6%9B%B2%E7%B7%9A%E6%9A%97%E5%8F%B7#Scalar_Multiplication
	curve25519.ScalarBaseMult((*[32]byte)(alice_publicKey), (*[32]byte)(alice_privateKey))
	curve25519.ScalarBaseMult((*[32]byte)(bob_publicKey), (*[32]byte)(bob_privateKey))

	// ECDHEの鍵交換をする
	a, _ := curve25519.X25519(alice_privateKey, bob_publicKey)
	b, _ := curve25519.X25519(bob_privateKey, alice_publicKey)

	fmt.Printf("alice's Shared key is   %x\n", b)
	fmt.Printf("bob's Shared key is   　%x\n", a)

}
