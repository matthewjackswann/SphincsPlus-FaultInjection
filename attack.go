package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/kasperdi/SPHINCSPLUS-golang/wots"
)

func main() {
	// sphincs+ parameters
	params := parameters.MakeSphincsPlusSHA256256fRobust(false)
	// create message to sign
	message := make([]byte, params.N)
	_, err := rand.Read(message)
	if err != nil {
		panic(err)
	}
	message = []byte{253, 233, 0, 195, 129, 64, 198, 174, 137, 13, 63, 86, 230, 21, 9, 200, 239, 40, 249, 191, 97, 75, 215, 198, 105, 39, 179, 105, 195, 229, 165, 189}

	// key gen
	sk, pk := sphincs.Spx_keygen(params)
	// sign correctly
	goodSignature := sphincs.Spx_sign(params, message, sk)
	fmt.Println(fmt.Sprintf("%x", sha256.Sum224(goodSignature.GetSIG_HT().GetXMSSSignature(16).WotsSignature)))
	//fmt.Println(fmt.Sprintf("%x", (goodSignature.GetSIG_HT().GetXMSSSignature(15).WotsSignature)))

	badSignature := sphincs.Spx_sign_fault(params, message, sk)
	fmt.Println(fmt.Sprintf("%x", sha256.Sum224(badSignature.GetSIG_HT().GetXMSSSignature(16).WotsSignature)))
	//fmt.Println(fmt.Sprintf("%x", (badSignature.GetSIG_HT().GetXMSSSignature(15).WotsSignature)))

	// check message verifies
	if !sphincs.Spx_verify(params, message, badSignature, pk) {
		_ = fmt.Errorf("verification failed")
	} else {
		fmt.Println("bad Success")
	}
	if !sphincs.Spx_verify(params, message, goodSignature, pk) {
		_ = fmt.Errorf("verification failed")
	} else {
		fmt.Println("good Success")
	}

	if !bytes.Equal(goodSignature.R, badSignature.R) {
		fmt.Println("Diff R")
	}

	for i := 0; i < len(goodSignature.SIG_HT.XMSSSignatures); i++ {
		if !bytes.Equal(badSignature.SIG_HT.XMSSSignatures[i].WotsSignature, goodSignature.SIG_HT.XMSSSignatures[i].WotsSignature) {
			fmt.Print("Diff block ")
			fmt.Println(i)
		}
	}

	for i := 0; i < len(goodSignature.SIG_HT.XMSSSignatures); i++ {
		if !bytes.Equal(badSignature.SIG_HT.XMSSSignatures[i].AUTH, goodSignature.SIG_HT.XMSSSignatures[i].AUTH) {
			fmt.Print("Diff AUTH ")
			fmt.Println(i)
		}
	}
}

func getMessageFromSignatureAndPK(sig []byte, pk []byte, params *parameters.Parameters, PKseed []byte, adrs *address.ADRS) []byte {
	// repeated hashes on sig should be equal to publicKey
	// number of hashes correspond to m (inc checksum)
	m := make([]byte, 0)

	for i := 0; i < params.Len; i++ {
		for c := 0; c < params.W; c++ {
			adrs.SetChainAddress(i)
			hashed := wots.Chain(params, sig[i*params.N:(i+1)*params.N], params.W-1-c, c, PKseed, adrs)
			if bytes.Equal(hashed, pk[i*params.N:(i+1)*params.N]) {
				m = append(m, byte(params.W-c-1))
				break
			}
			if c == params.W-1 {
				panic("Noooooo")
			}
		}
	}

	return m
}
