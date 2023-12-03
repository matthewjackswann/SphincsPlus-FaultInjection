package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/kasperdi/SPHINCSPLUS-golang/util"
	"github.com/kasperdi/SPHINCSPLUS-golang/wots"
	"math"
	"os"
	"time"
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
	fmt.Println("Signing faulty messages. Press enter to stop")

	// maintain list of the fewest times hashed sk and how many times it was hashed
	smallestSignature := make([]byte, len(ots_sig))
	copy(smallestSignature, ots_sig)
	hashCount := msgToBaseW(params, message)

	userInput := waitForUserInput()
	searching := true
	for searching { // keep looping until the user presses enter
		select {
		case <-userInput:
			searching = false // if user has entered input stop
		default:
			// sign the same message but cause a fault
			oracleInputFaulty <- message
			badSig := <-oracleResponseFaulty
			badWotsSig := badSig.SIG_HT.GetXMSSSignature(16).WotsSignature

			// try to recreate message from signature, with h =64 and d = 8 this has a 1/16 chance of success
			success, faultyMessage := getWOTSMessageFromSignatureAndPK(badWotsSig, ots_pk, params, pk.PKseed, tree)
			if success { // message was signed with ots_pk
				smaller := false
				for block := 0; block < params.Len; block++ {
					// if a sig with fewer hashes of a sk if found, update the smallest signature
					if hashCount[block] > faultyMessage[block] {
						smaller = true
						copy(smallestSignature[block*params.N:(block+1)*params.N], badWotsSig[block*params.N:(block+1)*params.N])
						hashCount[block] = faultyMessage[block]
					}
				}
				if smaller {
					fmt.Print("New smallest signature: ")
					fmt.Println(hashCount)
				} else {
					fmt.Println("New non-smaller signature found")
				}
			}
		}
	}

	oracleInput <- nil                 // stop oracle thread
	time.Sleep(100 * time.Millisecond) // wait for oracle to finish

	fmt.Print("We can now sign anything given each block of the message is strictly greater than: ")
	fmt.Println(hashCount)
	fmt.Printf("The corresponding smallest signature is %x\n", smallestSignature)
}

func createSigningOracle(params *parameters.Parameters) (*sphincs.SPHINCS_PK, chan []byte, chan *sphincs.SPHINCS_SIG, chan []byte, chan *sphincs.SPHINCS_SIG) {
	sk, pk := sphincs.Spx_keygen(params)
	messageChan := make(chan []byte)
	signatureChan := make(chan *sphincs.SPHINCS_SIG)

	messageChanFault := make(chan []byte)
	signatureChanFault := make(chan *sphincs.SPHINCS_SIG)

	validSigns := 0
	faultySigns := 0

	go func() {
		responding := true
		for responding {
			select {
			case m := <-messageChan:
				if m == nil {
					responding = false
					break
				}
				validSigns += 1
				signatureChan <- sphincs.Spx_sign_debug(params, m, sk)
			case m := <-messageChanFault:
				if m == nil {
					responding = false
					break
				}
				faultySigns += 1
				signatureChanFault <- sphincs.Spx_sign_fault(params, m, sk)
			}
		}
		fmt.Println("Oracle stopping")
		fmt.Printf("Signed correctly: %d\n", validSigns)
		fmt.Printf("Signed with fault: %d\n", faultySigns)
	}()

	return pk, messageChan, signatureChan, messageChanFault, signatureChanFault
}

func waitForUserInput() chan interface{} {
	userInput := make(chan interface{})
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		userInput <- new(interface{})
	}()
	return userInput
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
	adrs := new(address.ADRS)
	adrs.SetLayerAddress(16) // target layer in the tree
	idx_leaf := 0
	for j := 1; j < params.D; j++ {
		idx_leaf = int(tree % (1 << uint64(params.H/params.D)))
		tree = tree >> (params.H / params.D)
	}
	adrs.SetKeyPairAddress(idx_leaf)

	// convert message to base w
	msg := msgToBaseW(params, message)

	sig := make([]byte, params.Len*params.N)

	for i := 0; i < params.Len; i++ {
		adrs.SetChainAddress(i)
		copy(sig[i*params.N:], wots.Chain(params, signature[i*params.N:(i+1)*params.N], msg[i], params.W-1-msg[i], PKseed, adrs))
	}

	return sig
}

func msgToBaseW(params *parameters.Parameters, message []byte) []int {
	msg := util.Base_w(message, params.W, params.Len1)

	// compute checksum
	csum := 0
	for i := 0; i < params.Len1; i++ {
		csum = csum + params.W - 1 - msg[i]
	}

	csum = csum << (8 - ((params.Len2 * int(math.Log2(float64(params.W)))) % 8))
	len2Bytes := int(math.Ceil((float64(params.Len2) * math.Log2(float64(params.W))) / 8))
	msg = append(msg, util.Base_w(util.ToByte(uint64(csum), len2Bytes), params.W, params.Len2)...)
	return msg
}
