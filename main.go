package main

import (
	"fmt"
	"math/big"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/elliptic"

	"encoding/json"
	"io/ioutil"
	"os"
	"encoding/hex"
	"bufio"


	"github.com/Solidity-RingSignature/CryptoNote1/util/ethereum/common"
	"github.com/Solidity-RingSignature/CryptoNote1/util/ethereum/abi"
	"github.com/Solidity-RingSignature/CryptoNote1/secp256k1"
	"github.com/Solidity-RingSignature/CryptoNote1"

)

type Voting struct {
	Id         uint64   `json:"id"`
	candidates []*ecdsa.PrivateKey
	voters     []*ecdsa.PrivateKey
	Candidates []string `json:"candidates"`
	Voters     []string `json:"voters"`
}

type Vote struct {
	Id             uint64
	Candidate      string
	PubKeys        []ecdsa.PublicKey
	SignerKey      ecdsa.PrivateKey
	SignerPosition int
}

func CreateRandVote(candidates, voters int) (Voting) {

	v := Voting{Id: randUint64(^uint64(0)),
		candidates: randPrivateKeys(candidates),
		voters: randPrivateKeys(voters),
	}
	v.Candidates = keysToString(v.candidates)
	v.Voters = keysToString(v.voters)
	return v
}

func keysToString(in []*ecdsa.PrivateKey) (out []string) {
	out = make([]string, len(in))
	for i, _ := range out {
		out[i] = hex.EncodeToString(in[i].D.Bytes())
	}
	return out
}

func stringToKeys(in []string) (out []*ecdsa.PrivateKey) {
	out = make([]*ecdsa.PrivateKey, len(in))
	for i, _ := range out {
		b, err := hex.DecodeString(in[i])
		check(err)
		sk, _ := secp256k1.PrivKeyFromScalar(b)
		out[i] = sk.ToECDSA()
	}
	return out
}

func randPrivateKeys(n int) (keys []*ecdsa.PrivateKey) {

	keys = make([]*ecdsa.PrivateKey, n)
	for i, _ := range keys {
		k, e := secp256k1.GeneratePrivateKey()
		check(e)
		keys[i] = k.ToECDSA()

	}
	return keys
}
func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {

	RandVote := CreateRandVote(3, 3)
	b, err := json.Marshal(RandVote)
	check(err)

	check(err)
	err = ioutil.WriteFile("test.json", b, 0644)
	check(err)

	// Open our jsonFile
	jsonFile, err := os.Open("test.json")
	// if we os.Open returns an error then handle it
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Successfully Opened test.json")
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	// read our opened xmlFile as a byte array.
	byteValue, _ := ioutil.ReadAll(jsonFile)

	// we initialize our Users array
	var vote Voting

	// we unmarshal our byteArray which contains our
	// jsonFile's content into 'users' which we defined above
	json.Unmarshal(byteValue, &vote)
	vote.candidates = stringToKeys(vote.Candidates)
	vote.voters = stringToKeys(vote.Voters)
	prepareSolidityCreateArgs(&vote)
	prepareSoliditiyVoteArgs(&vote)

}
func prepareSoliditiyVoteArgs(v *Voting) {
	f, err := os.Create("vote.txt")
	check(err)
	defer f.Close()
	w := bufio.NewWriter(f)
	w.WriteString("arguments for VoteAnnonymous(...)\n")

	for pos, voter := range v.voters {

		candidate := PubkeyToAddress(&v.candidates[randUint64(uint64(len(v.candidates)))].PublicKey)

		var sig = CryptoNote1.NewLSAG(voter)

		pkps := privateToPub(v.voters)

		sig.Sign(v.Id, candidate, pkps, voter, pos)
		if !sig.Verify(v.Id, candidate, pkps) {
			panic(fmt.Sprintf("Verification failed at %v", pos))
		}

		w.WriteString("\n\n")
		w.WriteString(fmt.Sprintf("Voter %v votes for candidate %v \n", voter.D.String(), candidate.String()))
		SolidityArgFormatting(w, nil, v.Id)
		w.WriteString(sep)
		SolidityArgFormatting(w, common.Address{}, candidate)
		w.WriteString(sep)
		SolidityArgFormatting(w,nil,sig.Ix)
		w.WriteString(sep)
		SolidityArgFormatting(w,nil,sig.Iy)
		w.WriteString(sep)
		SolidityArgFormatting(w,nil,sig.Ci[0])
		w.WriteString(sep)
		SolidityArgFormatting(w, nil, sig.Si)
	}
	w.Flush()
}

func privateToPub(in []*ecdsa.PrivateKey) (out []*ecdsa.PublicKey) {
	out = make([]*ecdsa.PublicKey, len(in))
	for i, _ := range out {
		out[i] = &in[i].PublicKey
	}
	return
}

func prepareSolidityCreateArgs(v *Voting) {
	f, err := os.Create("solargs.txt")
	check(err)
	defer f.Close()
	w := bufio.NewWriter(f)
	w.WriteString("arguments for createVote(...)\n")

	SolidityArgFormatting(w, nil, v.Id)
	w.WriteString(sep)
	SolidityArgFormatting(w, common.Address{}, v.candidates)

	w.WriteString("\narguments for addVotersToVote(...)\n")
	SolidityArgFormatting(w, nil, v.Id)
	w.WriteString(sep)
	SolidityArgFormatting(w, xCoord{}, v.voters)
	w.WriteString(sep)
	SolidityArgFormatting(w, yCoord{}, v.voters)
	//threshold
	w.WriteString(sep)
	w.WriteString(fmt.Sprintf("%v", len(v.voters)))
	//ready
	w.WriteString(sep)
	w.WriteString("true")
	w.Flush()
}

var app = "\""
var sep = ","
var left = "["
var right = "]"

type xCoord struct{}
type yCoord struct{}

func SolidityArgFormatting(io *bufio.Writer, formatInto interface{}, input interface{}) {
	switch v := input.(type) {
	case common.Address:
		io.WriteString(app + v.String() + app)
	case *big.Int:

		io.WriteString(app + v.String() + app)

	case []*big.Int:
		io.WriteString(left)
		for i := 0; i < len(v)-1; i++ {
			io.WriteString(app + v[i].String() + app + sep)
		}
		io.WriteString(app + v[len(v)-1].String() + app + right)
	case []*ecdsa.PrivateKey:
		switch formatInto.(type) {
		case common.Address:
			io.WriteString(left)
			for i := 0; i < len(v)-1; i++ {
				io.WriteString(app + PubkeyToAddress(&v[i].PublicKey).String() + app + sep)
			}
			io.WriteString(app + PubkeyToAddress(&v[len(v)-1].PublicKey).String() + app + right)
		case xCoord:
			io.WriteString(left)
			for i := 0; i < len(v)-1; i++ {
				io.WriteString(app + v[i].X.String() + app + sep)
			}
			io.WriteString(app + v[len(v)-1].X.String() + app + right)
		case yCoord:
			io.WriteString(left)
			for i := 0; i < len(v)-1; i++ {
				io.WriteString(app + v[i].Y.String() + app + sep)
			}
			io.WriteString(app + v[len(v)-1].Y.String() + app + right)
		default:
		}
	case *ecdsa.PrivateKey:
		switch formatInto.(type) {
		case common.Address:
			io.WriteString(app + PubkeyToAddress(&v.PublicKey).String() + app)
		}

	case uint64:
		io.WriteString(app + fmt.Sprintf("%v", v) + app)
	default:
		panic("not supported")
	}
}

func PubkeyToAddress(p *ecdsa.PublicKey) common.Address {
	pubBytes := FromECDSAPub(p)
	return common.BytesToAddress(abi.Keccak256(pubBytes[1:])[12:])
}

func FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(secp256k1.S256(), pub.X, pub.Y)
}

func randUint64(max uint64) uint64 {
	nBig, err := rand.Int(rand.Reader, new(big.Int).SetUint64(max))
	if err != nil {
		panic(err)
	}
	n := nBig.Uint64()
	return n
}
