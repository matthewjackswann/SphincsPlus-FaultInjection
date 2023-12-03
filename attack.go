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
	params := parameters.MakeSphincsPlusSHA256256fRobust(true)

	// create random message to sign
	message := make([]byte, params.N)
	_, err := rand.Read(message)
	if err != nil {
		panic(err)
	}

	// createSigningOracle returns only the public key and channels for messages and signatures
	pk, oracleInput, oracleResponse, oracleInputFaulty, oracleResponseFaulty := createSigningOracle(params)

	// sign correctly
	oracleInput <- message
	goodSignature := <-oracleResponse
	success, ots_msg, ots_sig, tree := sphincs.Spx_verify_get_msg_sig_tree(params, message, goodSignature, pk)
	if !success {
		panic("Good signature didn't sign :(")
	}

	ots_pk := getWOTSPKFromMessageAndSignature(params, ots_sig, ots_msg, pk.PKseed, tree)

	fmt.Println("Signed message")
	fmt.Printf("Public key used for WOTS in last layer: %x\n", ots_pk)

	for i := 0; i < 100; i++ {
		// sign the same message but cause a fault
		oracleInputFaulty <- message
		badSig := <-oracleResponseFaulty

		// try to recreate message from signature, with h =64 and d = 8 this has a 1/16 chance of success
		success, faultyMessage := getWOTSMessageFromSignatureAndPK(badSig.SIG_HT.GetXMSSSignature(16).WotsSignature, ots_pk, params, pk.PKseed, tree)
		if success { // message was signed with ots_pk
			fmt.Println(faultyMessage)
		}
	}

	oracleInput <- nil // stop oracle thread
}

func createSigningOracle(params *parameters.Parameters) (*sphincs.SPHINCS_PK, chan []byte, chan *sphincs.SPHINCS_SIG, chan []byte, chan *sphincs.SPHINCS_SIG) {
	sk, pk := sphincs.Spx_keygen(params)
	messageChan := make(chan []byte, 1)
	signatureChan := make(chan *sphincs.SPHINCS_SIG, 1)

	messageChanFault := make(chan []byte, 1)
	signatureChanFault := make(chan *sphincs.SPHINCS_SIG, 1)

	go func() {
		for {
			select {
			case m := <-messageChan:
				if m == nil {
					return // stop
				}
				signatureChan <- sphincs.Spx_sign(params, m, sk)
			case m := <-messageChanFault:
				if m == nil {
					return // stop
				}
				signatureChanFault <- sphincs.Spx_sign_fault(params, m, sk)
			}

		}
	}()

	return pk, messageChan, signatureChan, messageChanFault, signatureChanFault
}

func getWOTSMessageFromSignatureAndPK(sig []byte, pk []byte, params *parameters.Parameters, PKseed []byte, tree uint64) (bool, []int) {
	// repeated hashes on sig should be equal to publicKey
	// number of hashes correspond to m (inc checksum)
	m := make([]int, 0)
	adrs := new(address.ADRS)
	adrs.SetLayerAddress(16) // target layer in the tree
	idx_leaf := 0
	for j := 1; j < params.D; j++ {
		idx_leaf = int(tree % (1 << uint64(params.H/params.D)))
		tree = tree >> (params.H / params.D)
	}
	adrs.SetKeyPairAddress(idx_leaf)

	for i := 0; i < params.Len; i++ {
		for c := 0; c < params.W; c++ {
			adrs.SetChainAddress(i)
			adrs.SetHashAddress(0)
			hashed := wots.Chain(params, sig[i*params.N:(i+1)*params.N], params.W-1-c, c, PKseed, adrs)
			if bytes.Equal(hashed, pk[i*params.N:(i+1)*params.N]) {
				m = append(m, params.W-c-1)
				break
			}
			if c == params.W-1 {
				return false, nil
			}
		}
	}

	return true, m
}

// Finds pk from signature, for verification
func getWOTSPKFromMessageAndSignature(params *parameters.Parameters, signature []byte, message []byte, PKseed []byte, tree uint64) []byte {
	csum := 0

	adrs := new(address.ADRS)
	adrs.SetLayerAddress(16) // target layer in the tree
	idx_leaf := 0
	for j := 1; j < params.D; j++ {
		idx_leaf = int(tree % (1 << uint64(params.H/params.D)))
		tree = tree >> (params.H / params.D)
	}
	adrs.SetKeyPairAddress(idx_leaf)

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

	return tmp
}
