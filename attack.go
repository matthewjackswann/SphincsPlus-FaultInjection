package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/kasperdi/SPHINCSPLUS-golang/util"
	"github.com/kasperdi/SPHINCSPLUS-golang/wots"
	"math"
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

	// key gen, sk is only used for signing
	pk, oracleInput, oracleResponse := createSigningOracle(params)
	// sign correctly
	oracleInput <- message

	goodSignature := <-oracleResponse

	success, ots_msg, ots_sig := sphincs.Spx_verify_get_msg_sig(params, message, goodSignature, pk)
	if !success {
		panic("Good signature didn't sign :(")
	}

	ots_pk := getWOTSPKFromMessageAndSignature(params, ots_sig, ots_msg, pk.PKseed)
	fmt.Println(ots_msg)
	fmt.Println(ots_sig)
	fmt.Println(ots_pk)

	oracleInput <- nil // stop oracle thread
}

func createSigningOracle(params *parameters.Parameters) (*sphincs.SPHINCS_PK, chan []byte, chan *sphincs.SPHINCS_SIG) {
	sk, pk := sphincs.Spx_keygen(params)
	messageChan := make(chan []byte)
	signatureChan := make(chan *sphincs.SPHINCS_SIG)

	go func() {
		for {
			m := <-messageChan
			if m == nil {
				return // stop
			}
			signatureChan <- sphincs.Spx_sign(params, m, sk)
		}
	}()

	return pk, messageChan, signatureChan
}

func getWOTSMessageFromSignatureAndPK(sig []byte, pk []byte, params *parameters.Parameters, PKseed []byte) []int {
	// repeated hashes on sig should be equal to publicKey
	// number of hashes correspond to m (inc checksum)
	m := make([]int, 0)
	adrs := new(address.ADRS)
	adrs.SetLayerAddress(16) // target layer in the tree

	for i := 0; i < params.Len; i++ {
		for c := 0; c < params.W; c++ {
			adrs.SetChainAddress(i)
			hashed := wots.Chain(params, sig[i*params.N:(i+1)*params.N], params.W-1-c, c, PKseed, adrs)
			if bytes.Equal(hashed, pk[i*params.N:(i+1)*params.N]) {
				m = append(m, params.W-c-1)
				break
			}
			if c == params.W-1 {
				panic("Noooooo")
			}
		}
	}

	return m
}

// Finds pk from signature, for verification
func getWOTSPKFromMessageAndSignature(params *parameters.Parameters, signature []byte, message []byte, PKseed []byte) []byte {
	csum := 0
	adrs := new(address.ADRS)
	adrs.SetLayerAddress(16) // target layer in the tree

	// Make a copy of adrs
	wotspkADRS := adrs.Copy()

	// convert message to base w
	msg := util.Base_w(message, params.W, params.Len1)

	// compute checksum
	for i := 0; i < params.Len1; i++ {
		csum = csum + params.W - 1 - msg[i]
	}

	csum = csum << (8 - ((params.Len2 * int(math.Log2(float64(params.W)))) % 8))
	len2_bytes := int(math.Ceil((float64(params.Len2) * math.Log2(float64(params.W))) / 8))
	msg = append(msg, util.Base_w(util.ToByte(uint64(csum), len2_bytes), params.W, params.Len2)...)

	tmp := make([]byte, params.Len*params.N)

	for i := 0; i < params.Len; i++ {
		adrs.SetChainAddress(i)
		copy(tmp[i*params.N:], wots.Chain(params, signature[i*params.N:(i+1)*params.N], msg[i], params.W-1-msg[i], PKseed, adrs))
	}

	wotspkADRS.SetType(address.WOTS_PK)
	wotspkADRS.SetKeyPairAddress(adrs.GetKeyPairAddress())

	return tmp
}
