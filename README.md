# Solidity-RingSignature
Ring-Signature using secp256k1 in Solidity for educational purpose.  Allows untracable voting and coin transfer within the EVM environment.
First implementation of "Linkable Spontaneous Anonymous Groups Signature [REF](https://bitcointalk.org/index.php?topic=972541.msg10619684#msg10619684)."-Verification in solidity.
secp256k1 is forked from [monax](https://github.com/monax/keys/tree/master/crypto/secp256k1)

##Note
LSAG-signature voting with 3 cosigners requires ≈ 12.34 mGas. ECC operations are costly^^ use a testnet!


## Guide
1. Deploy secp256k1.sol on an ethereum chain
2. Deploy UntraceableVoting.sol (pass the secp256k1 contract address in the constructor)
3. Run main.go, to create a random set of "n voters and m candidates" and "signatures for each voter, to vote on on of the randomly selected candidates"
    4. copy the newly generated text in solargs.txt and pass them as arguments for the creation and setup a voting on the chain
    5. in vote.txt you'll find randomly generated valid vote parameters, pass them as argument for AnnonymousVote(..) function in UntraceableVoting.sol



## Requirements

[Go](http://golang.org) 1.9 or newer.

## Getting Started

- Solidity-RingSignature (and utilities) will now be installed in either ```$GOROOT/bin``` or
  ```$GOPATH/bin``` depending on your configuration.  If you did not already
  add the bin directory to your system path during Go installation, we
  recommend you do so now.

## Updating

#### Windows

Install a newer MSI

#### Linux/BSD/MacOSX/POSIX - Build from Source

- **Dep**

  Dep is used to manage project dependencies and provide reproducible builds.
  To install:

  `go get -u github.com/golang/dep/cmd/dep`

Unfortunately, the use of `dep` prevents a handy tool such as `go get` from
automatically downloading, building, and installing the source in a single
command.  Instead, the latest project and dependency sources must be first
obtained manually with `git` and `dep`, and then `go` is used to build and
install the project.

**Getting the source**:

For a first time installation, the project and dependency sources can be
obtained manually with `git` and `dep` (create directories as needed):

```
git clone https://github.com/mottla/Solidity-RingSignature.git
cd $GOPATH/src/github.com/Solidity-RingSignature
dep ensure
go install . ./cmd/...
```

To update an existing source tree, pull the latest changes and install the
matching dependencies:

```
cd $GOPATH/src/github.com/Solidity-RingSignature
git pull
dep ensure
go install . ./cmd/...
```

