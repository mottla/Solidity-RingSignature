// Copyright (c) 2018-2019 by mottla
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
package CryptoNote1

import (
	"fmt"
	"math/big"
	"io"
	"crypto/elliptic"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"bytes"

	"github.com/Solidity-RingSignature/CryptoNote1/secp256k1"
	"github.com/Solidity-RingSignature/CryptoNote1/util/ethereum/common"

	"github.com/Solidity-RingSignature/CryptoNote1/util/miguelmota/go-solidity-sha3"
)

var defaultCurve = secp256k1.S256()


//returns a new Linkable Spontaneous Anonymous Group Signature Struct.
//if key is set, ls can be used for signing and verification. If not, ls can be used for verification only
func NewLSAG(key *ecdsa.PrivateKey) (ls *LSAGsignature) {
	ls = new(LSAGsignature)

	ls.Curve = defaultCurve

	if key != nil {
		ls.AddKeyImage(key)
	}
	return
}

type RingSignature interface {
	Sign(id uint64, candidate common.Address, pubKeys []*ecdsa.PublicKey, signerKey *ecdsa.PrivateKey, signerPosition int)
	Verify(id uint64, candidate common.Address, pubKeys []*ecdsa.PublicKey) bool
	hashToEcc(x, y *big.Int) (hx, hy *big.Int)
	AddKeyImage(priv *ecdsa.PrivateKey)
}

func (s *LSAGsignature) GetCurve() elliptic.Curve {
	return s.Curve
}

type LSAGsignature struct {
	Sigma
	elliptic.Curve
}


//hash with padding as its done in solidity.
func customHash(id uint64, candidate common.Address, Lix, Liy, Rix, Riy *big.Int) (hash []byte) {
	hash = solsha3.SoliditySHA3(
		solsha3.Uint64(id),
		solsha3.Address(candidate),
		solsha3.Uint256(Lix),
		solsha3.Uint256(Liy),
		solsha3.Uint256(Rix),
		solsha3.Uint256(Riy),
	)
	return
}

//create a Linkable Spontaneous Anonymous Groups Signature
//asserts that the calling Sigma was prepared properly by calling PrepareRingSig_random(..) before
//produces a ring signature on a given Curve for a given message as input using the scheme in
//https://bitcointalk.org/index.php?topic=972541.msg10619684#msg10619684
//note that len(Sigma.Ci) =1 != len(Sigma.Si)=len(pubKeys), and therefore the signature requires approximately
//half the storage as a Traceable Ring Signature produced by SignTRS(...)
func (s *LSAGsignature) Sign(id uint64, candidate common.Address, pubKeys []*ecdsa.PublicKey, signerKey *ecdsa.PrivateKey, signerPosition int) {

	s.Si = make([]*big.Int, len(pubKeys))
	var Lix, Liy *big.Int
	var Rix, Riy *big.Int
	var hash []byte
	var x1, x2, x4, x3 *big.Int
	var t1, t2 *big.Int
	Curve := s.Curve
	j := int(signerPosition+1) % len(pubKeys)
	alpha := RandFieldElement(Curve)
	Lix, Liy = Curve.ScalarBaseMult(alpha.Bytes())
	t1, t2 = s.hashToEcc(pubKeys[signerPosition].X, pubKeys[signerPosition].Y)
	Rix, Riy = Curve.ScalarMult(t1, t2, alpha.Bytes())

	hash = customHash(id,candidate,Lix,Liy,Rix,Riy)

	if j == 0 {
		s.Ci = []*big.Int{new(big.Int).SetBytes(hash)}
	}

	for counter := 0; counter < len(pubKeys)-1; counter++ {
		s.Si[j] = RandFieldElement(Curve)
		x1, x2 = Curve.ScalarBaseMult(s.Si[j].Bytes())
		x3, x4 = Curve.ScalarMult(pubKeys[j].X, pubKeys[j].Y, hash)
		Lix, Liy = Curve.Add(x1, x2, x3, x4)
		t1, t2 = s.hashToEcc(pubKeys[j].X, pubKeys[j].Y)
		x1, x2 = Curve.ScalarMult(t1, t2, s.Si[j].Bytes())
		x3, x4 = Curve.ScalarMult(s.Ix, s.Iy, hash)
		Rix, Riy = Curve.Add(x1, x2, x3, x4)
		hash = customHash(id,candidate,Lix,Liy,Rix,Riy)
		j++
		j %= len(pubKeys)
		if j == 0 {
			s.Ci = []*big.Int{new(big.Int).SetBytes(hash)}
		}
	}

	s.Si[j] = new(big.Int)
	s.Si[j].Sub(alpha, new(big.Int).Mul(new(big.Int).SetBytes(hash), signerKey.D))
	s.Si[j].Mod(s.Si[j], Curve.Params().N)
}

//checks weather the given LSAG signature is valid according to verification rules in MRL-0005
//returns true if valid, false otherwise
func (s *LSAGsignature) Verify(id uint64, candidate common.Address,  pubKeys []*ecdsa.PublicKey) bool {
	if len(s.Ci) != 1 || len(s.Si) != len(pubKeys) {
		fmt.Println("improper prepared signature")
		return false
	}
	Curve := s.Curve

	ci := make([][]byte, 2)
	//fmt.Printf("\nStart verify with %x into c0 ",s.Ci[0].Bytes())


	ci[0] = s.Ci[0].Bytes()
	//fmt.Printf("\nckeck again %x ",ci)
	var Lix, Liy *big.Int
	var Rix, Riy *big.Int
	var x1, x2, x4, x3 *big.Int
	var t1, t2 *big.Int

	for i, sj := range s.Si {
		x1, x2 = Curve.ScalarBaseMult(sj.Bytes())
		x3, x4 = Curve.ScalarMult(pubKeys[i].X, pubKeys[i].Y, ci[i%2])
		Lix, Liy = Curve.Add(x1, x2, x3, x4)
		t1, t2 = s.hashToEcc(pubKeys[i].X, pubKeys[i].Y)
		x3, x4 = Curve.ScalarMult(s.Ix, s.Iy, ci[i%2])
		x1, x2 = Curve.ScalarMult(t1, t2, sj.Bytes())
		Rix, Riy = Curve.Add(x1, x2, x3, x4)
		//sep:="\""
		//fmt.Printf(sep+"%v"+sep+","+sep+"%v"+sep+","+sep+"%v"+sep+","+sep+"%v"+sep+","+sep+"%v"+sep+","+sep+"%v"+sep,candidate.String(),id,Lix.String(),Liy.String(),Rix.String(),Riy.String())
		h:=customHash(id,candidate,Lix,Liy,Rix,Riy)
		//fmt.Println("\nresulting hash")
		//fmt.Println(new(big.Int).SetBytes(h).String())
		ci[(i+1)%2] = h

	}
	if bytes.Equal(ci[len(pubKeys)%2], s.Ci[0].Bytes()) {
		return true
	}
	return false

}

type Sigma struct {
	Ix, Iy *big.Int //keyimage I=xH(P)
	//position of signer Public Key in the pubKeys Array. Should be assigned randomly.
	Ci []*big.Int //commitment for TRS. In LSAG only len(Ci)=1
	Si []*big.Int //commitment for LSAG and TRS
}

func (s LSAGsignature) String() string {
	return fmt.Sprintf("\nKeyImage[%x,%x]\nCi %v\nRi%v \n", s.Ix, s.Iy, s.Ci, s.Si)
}

func (s Sigma) String() string {
	return fmt.Sprintf("\nKeyImage[%x,%x]\nCi %v\nRi%v \n", s.Ix, s.Iy, s.Ci, s.Si)
}


var one = new(big.Int).SetInt64(1)
// RandFieldElement returns a random element of the field underlying the given
// Curve using the procedure given in [NSA] A.2.1.
func RandFieldElement(c elliptic.Curve) (k *big.Int) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic("random failed..")
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

//Used as Hp in Whitepaper.
//Maps Field element to a Field element of the corresponding Curve.
//returns a deterministic random point on the Curve
//not that its unnecessary to use a cryptographic hash function here.. though why not^^
func (s *LSAGsignature) hashToEcc(x, y *big.Int) (hx, hy *big.Int) {
	hash := solsha3.SoliditySHA3(
		solsha3.Uint256(x),
		solsha3.Uint256(y),
	)

	hx, hy = s.Curve.ScalarBaseMult(hash)
	return

}

//Initializes the Key Image which is necessary for signing, validating and the prevention of doublespending after all
func (s *LSAGsignature) AddKeyImage(priv *ecdsa.PrivateKey) {
	hx, hp := s.hashToEcc(priv.X, priv.Y)

	//TODO check if priv.getD == priv.serialize
	s.Ix, s.Iy = s.Curve.ScalarMult(hx, hp, priv.D.Bytes())

	return
}

// creates a signature template with random cosigners and random signer position
// usefull for testing
func PrepareRingSig_random(in RingSignature, cosigners int) (signerPosition int, signerPrivatekey *ecdsa.PrivateKey, pkps []*ecdsa.PublicKey) {
	b := make([]byte, 4)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		panic("rand failed")
	}
	signerPosition = int(binary.BigEndian.Uint32(b))
	if cosigners == 0 {
		signerPosition = 0
	} else {
		signerPosition %= (cosigners + 1)
	}
	privs, pkps := randKeySet( cosigners+1)
	//privs, pkps := randPrivScalarKeyList2(edwards.Edwards(), cosigners+1)
	signerPrivatekey = privs[signerPosition]
	in.AddKeyImage(signerPrivatekey)
	return signerPosition, signerPrivatekey, pkps
}

//returns a set of deterministic-randomely generated public and corresponding privatekeys
func randKeySet( i int) (privates []*ecdsa.PrivateKey, publics []*ecdsa.PublicKey) {
	//r := mr.New(mr.NewSource(randSeed))
	curve:=secp256k1.S256()
	privates = make([]*ecdsa.PrivateKey, i)
	publics = make([]*ecdsa.PublicKey, i)
	for j := 0; j < i; j++ {
		rand := RandFieldElement(curve)
		x, y := curve.ScalarBaseMult(rand.Bytes())
		publics[j] = &ecdsa.PublicKey{Y: y, X: x}
		privates[j] = &ecdsa.PrivateKey{D: rand, PublicKey: *publics[j]}
	}
	return
}

