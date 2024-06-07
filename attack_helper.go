package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/fatih/color"
	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/kasperdi/SPHINCSPLUS-golang/util"
	"github.com/kasperdi/SPHINCSPLUS-golang/wots"
	"math"
	"os"
)

func getWOTSMessageFromSignatureAndPK(sig []byte, pk []byte, params *parameters.Parameters, PKseed []byte, idxLeaf int) (bool, []int) {
	// repeated hashes on sig should be equal to publicKey
	// number of hashes correspond to m (inc checksum)
	m := make([]int, 0)
	adrs := new(address.ADRS)
	adrs.SetLayerAddress(16) // target layer in the tree
	adrs.SetKeyPairAddress(idxLeaf)

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
func getWOTSPKFromMessageAndSignature(params *parameters.Parameters, signature []byte, message []byte, PKseed []byte, idxLeaf int) []byte {
	adrs := new(address.ADRS)
	adrs.SetLayerAddress(16) // target layer in the tree
	adrs.SetKeyPairAddress(idxLeaf)

	// convert message to base w
	msg := msgToBaseW(params, message)

	sig := make([]byte, params.Len*params.N)

	for i := 0; i < params.Len; i++ {
		adrs.SetChainAddress(i)
		adrs.SetHashAddress(0)
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

func getLastTreeIdxFromMsg(params *parameters.Parameters, R []byte, PK *sphincs.SPHINCS_PK, M []byte) uint64 {
	idxTree := getTreeIdxFromMsg(params, R, PK, M)

	for j := 1; j < params.D-1; j++ {
		idxTree = idxTree >> (params.H / params.D)
	}
	return idxTree
}

func getTreeIdxFromMsg(params *parameters.Parameters, R []byte, PK *sphincs.SPHINCS_PK, M []byte) uint64 {
	// compute message digest and index
	digest := params.Tweak.Hmsg(R, PK.PKseed, PK.PKroot, M)

	tmpMdBytes := int(math.Floor(float64(params.K*params.A+7) / 8))
	tmpIdxTreeBytes := int(math.Floor(float64(params.H-params.H/params.D+7) / 8))
	tmpIdxTree := digest[tmpMdBytes:(tmpMdBytes + tmpIdxTreeBytes)]

	idxTree := uint64(util.BytesToUint64(tmpIdxTree) & (math.MaxUint64 >> (64 - (params.H - params.H/params.D))))

	return idxTree
}

func forgeOTSignature(params *parameters.Parameters, hashCount, messageBlocks []int, minimalSignature, PKseed []byte, idxLeaf uint64) []byte {
	adrs := new(address.ADRS)
	adrs.SetLayerAddress(16) // target layer in the tree
	adrs.SetKeyPairAddress(int(idxLeaf))
	newSig := make([]byte, params.Len*params.N)

	for i := 0; i < params.Len; i++ {
		adrs.SetChainAddress(i)
		adrs.SetHashAddress(0)
		copy(newSig[i*params.N:], wots.Chain(params, minimalSignature[i*params.N:(i+1)*params.N], hashCount[i], messageBlocks[i]-hashCount[i], PKseed, adrs))
	}

	return newSig
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

func printIntArrayPadded(arr []int) {
	fmt.Print("[")
	for i := 0; i < len(arr); i++ {
		fmt.Printf("%02d ", arr[i])
	}
	fmt.Println("]")
}

func printHashCountVsMessageBlocks(messageBlocks, hashCount []int) {
	c := color.New(color.FgRed)
	fmt.Print("[")
	for i := 0; i < len(messageBlocks); i++ {
		if messageBlocks[i] < hashCount[i] {
			if _, err := c.Printf("%02d ", hashCount[i]); err != nil {
				panic("error printing in colour")
			}
		} else {
			fmt.Printf("%02d ", hashCount[i])
		}
	}
	fmt.Println("]")

	c = color.New(color.FgGreen)
	fmt.Print("[")
	for i := 0; i < len(messageBlocks); i++ {
		if messageBlocks[i] >= hashCount[i] {
			if _, err := c.Printf("%02d ", messageBlocks[i]); err != nil {
				panic("error printing in colour")
			}
		} else {
			fmt.Printf("%02d ", messageBlocks[i])
		}
	}
	fmt.Println("]")

}

func appendToFile(filename string, line string) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}

	if _, err = f.WriteString(line + "\n"); err != nil {
		panic(err)
	}

	if err = f.Close(); err != nil {
		panic(err)
	}
}
