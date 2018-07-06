// Copyright (c) 2018-2019 by mottla
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
package CryptoNote1

import (
	"testing"
	"fmt"
	"crypto/elliptic"
	"math/big"
	"github.com/Solidity-RingSignature/CryptoNote1/secp256k1"

	"github.com/Solidity-RingSignature/CryptoNote1/util/ethereum/abi"
	"github.com/Solidity-RingSignature/CryptoNote1/util/miguelmota/go-solidity-sha3"
	"github.com/Solidity-RingSignature/CryptoNote1/util/ethereum/common"
	"crypto/ecdsa"
	"crypto/rand"
)

//for comparsion with solidity results
func TestCustomHash(t *testing.T) {
	id := randInt(23452345)
	addr := randEthAddress()
	sk1, _ := secp256k1.GeneratePrivateKey()
	sk2, _ := secp256k1.GeneratePrivateKey()
	var sep= "\""
	fmt.Printf(sep+"%v"+sep+","+sep+"%v"+sep+","+sep+"%v"+sep+","+sep+"%v"+sep+","+sep+"%v"+sep+","+sep+"%v"+sep, id, addr.String(), sk1.X.String(), sk1.Y.String(), sk2.X.String(), sk2.Y.String())
	hash1 := solsha3.SoliditySHA3(
		solsha3.Uint64(id),
		solsha3.Address(addr),
		solsha3.Uint256(sk1.X),
		solsha3.Uint256(sk1.Y),
		solsha3.Uint256(sk2.X),
		solsha3.Uint256(sk2.Y),

	)
	fmt.Println("\n%v", new(big.Int).SetBytes(hash1).String())

}

//outputs some curve operations, which then can be compared to solidity ecc.sol contract results. worked all fine^^ believe me!!
func TestSolidityCurve(t *testing.T) {
	c := secp256k1.S256();
	pk, _ := secp256k1.GeneratePrivateKey()
	fmt.Printf("private key 1: %v", pk.D);
	fmt.Printf("\n %v %v", pk.X, pk.Y)

	p2, _ := secp256k1.GeneratePrivateKey()
	fmt.Printf("\n privatekey 2: %v", p2.D);
	fmt.Printf("\n %v %v", p2.X, p2.Y)

	fmt.Printf("\n \"%v\",\"%v\",\"%v\",\"%v\"", pk.X, pk.Y, p2.X, p2.Y)
	b1 := new(big.Int).SetInt64(2)

	a1, a2 := c.Add(pk.X, pk.Y, p2.X, p2.Y)
	//a1, a2 := c.Add(b1, b1, b1, b1)

	fmt.Printf("\nAdd %v %v", a1, a2)

	a1, a2 = hashToEcc(pk.X, pk.Y)
	fmt.Printf("\nHashTOEcc %v %v", a1, a2)

	a1, a2 = c.ScalarMult(pk.X, pk.Y, b1.Bytes())
	fmt.Printf("\n ScalarMul %v %v", a1, a2)
	a1, a2 = c.Double(pk.X, pk.Y)
	fmt.Printf("\n Double %v %v", a1, a2)
	a1, a2 = c.ScalarBaseMult(pk.D.Bytes())
	fmt.Printf("\n ScalarBaseMul %v %v", a1, a2)

}

func hashToEcc(x, y *big.Int) (hx, hy *big.Int) {
	hash := solsha3.SoliditySHA3(
		solsha3.Uint256(x),
		solsha3.Uint256(y),
	)

	hx, hy = secp256k1.S256().ScalarBaseMult(hash)
	return

}



func TestSignVerify_LSAG(t *testing.T) {

	for i := 1; i < 16; i += 2 {
		var sig = NewLSAG(nil)
		id := uint64(randInt(1234123454))
		candidate := randEthAddress()
		sigpos, privatekey, pkps := PrepareRingSig_random(sig, int(randInt(int64(i))))
		sig.Sign(id, candidate, pkps, privatekey, sigpos)

		if !sig.Verify(id, candidate, pkps) {
			t.Error("Verification failed")
			return
		}

		//lets mess with the verification process
		//alter random bit at message
		//sigpos, privatekey, pkps = PrepareRingSig_random(sig, randSeed, 5)
		//sig.Sign(id, candidate, pkps, privatekey, sigpos)
		//fmt.Println("\n candidate \n")
		//fmt.Println(candidate.String())

		pos := randInt(int64(len(candidate.Bytes())))
		bitPos := randInt(int64(8))
		alteredBytes := candidate.Bytes()
		alteredBytes[pos] ^= 1 << uint8(bitPos)
		candidate.SetBytes(alteredBytes)

		//fmt.Println(candidate.String())


		if sig.Verify(id, candidate, pkps) {
			t.Error("Verification expected to fail")
			return
		}

		//alter random bit at public key
		sigpos, privatekey, pkps = PrepareRingSig_random(sig, 5)
		sig.Sign(id, candidate, pkps, privatekey, sigpos)

		pos = randInt(int64(len(pkps)))
		bitPos = randInt(int64(8))
		alteredbytes := pkps[pos].Y.Bytes()
		alteredbytes[randInt(int64(len(alteredbytes)))] ^= 1 << uint8(bitPos)
		pkps[pos].Y.SetBytes(alteredbytes)
		if sig.Verify(id, candidate, pkps) {
			t.Error("Verification expected to fail")
			return
		}
	}

}


//HELPER FUNCTIONS
func randInt(max int64) int64 {
	nBig, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(err)
	}
	n := nBig.Int64()
	return n
}

func randEthAddress() common.Address {
	key, _ := secp256k1.GeneratePrivateKey()
	return PubkeyToAddress(key.PublicKey)

}
func PubkeyToAddress(p ecdsa.PublicKey) common.Address {
	pubBytes := FromECDSAPub(&p)
	return common.BytesToAddress(abi.Keccak256(pubBytes[1:])[12:])
}

func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(secp256k1.S256(), pub.X, pub.Y)
}
