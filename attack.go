package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"os"
)

func main() {

	// sphincs+ parameters
	params := parameters.MakeSphincsPlusSHA256256fRobust(true)

	// create random message to sign
	goodMessage := make([]byte, params.N)
	_, err := rand.Read(goodMessage)
	if err != nil {
		panic(err)
	}

	// createSigningOracle returns only the public key and channels for messages and signatures
	pk, oracleInput, oracleResponse, oracleInputFaulty, oracleResponseFaulty := createSigningOracle(params)
	// sign correctly
	oracleInput <- goodMessage
	goodSignature := <-oracleResponse

	smallestSignature, hashCount, targetIdxTree :=
		faultySignAndCreateSmallestSignature(goodMessage, goodSignature, oracleInputFaulty, oracleResponseFaulty, params, pk)

	oracleInput <- nil // stop oracle thread

	fmt.Print("We can now sign anything given each block of the message is strictly greater than: ")
	fmt.Println(hashCount)
	fmt.Printf("The corresponding smallest signature is %x\n", smallestSignature)

	// create message to try and forge a signature for
	forgedMessage := make([]byte, params.N)
	_, err = rand.Read(forgedMessage)
	if err != nil {
		panic(err)
	}

	forgedSignature := forgeMessageSignature(params, forgedMessage, pk, targetIdxTree, goodSignature, hashCount, smallestSignature)

	// check our forged message signs. We had no knowledge of sk :)
	if sphincs.Spx_verify(params, forgedMessage, forgedSignature, pk) {
		fmt.Println("It works!!!!")
	} else {
		fmt.Println("Didn't quite work :(")
	}

}

func faultySignAndCreateSmallestSignature(
	goodMessage []byte, goodSignature *sphincs.SPHINCS_SIG, oracleInputFaulty chan []byte, oracleResponseFaulty chan *sphincs.SPHINCS_SIG,
	params *parameters.Parameters, pk *sphincs.SPHINCS_PK) ([]byte, []int, uint64) {

	fmt.Println("Signing faulty messages. Press enter to stop")
	success, otsMsg, otsSig, tree := sphincs.Spx_verify_get_msg_sig_tree(params, goodMessage, goodSignature, pk)
	if !success {
		panic("Good signature didn't sign :(")
	}

	// maintain list of the fewest times hashed sk and how many times it was hashed
	smallestSignature := make([]byte, len(otsSig))
	copy(smallestSignature, otsSig)
	hashCount := msgToBaseW(params, otsMsg)

	otsPk := getWOTSPKFromMessageAndSignature(params, otsSig, otsMsg, pk.PKseed, tree)

	userInput := waitForUserInput()
	searching := true
	for searching { // keep looping until the user presses enter
		select {
		case <-userInput:
			searching = false // if user has entered input stop
		default:
			// sign the same message but cause a fault
			oracleInputFaulty <- goodMessage
			badSig := <-oracleResponseFaulty
			badWotsSig := badSig.SIG_HT.GetXMSSSignature(16).WotsSignature

			// try to recreate message from signature, with h =64 and d = 8 this has a 1/16 chance of success
			success, faultyMessage := getWOTSMessageFromSignatureAndPK(badWotsSig, otsPk, params, pk.PKseed, tree)
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

	targetIdxTree := tree
	for j := 1; j < params.D-1; j++ {
		targetIdxTree = targetIdxTree >> (params.H / params.D)
	}

	return smallestSignature, hashCount, targetIdxTree
}

func forgeMessageSignature(params *parameters.Parameters, message []byte, pk *sphincs.SPHINCS_PK, targetIdxTree uint64,
	goodSignature *sphincs.SPHINCS_SIG, hashCount []int, smallestSignature []byte) *sphincs.SPHINCS_SIG {

	for {
		// key pair used to create hypertree to forge signature with
		fSk, _ := sphincs.Spx_keygen(params)
		// check partialFSig signed with pk last tree_idx is the same as with signing with fPk
		partialFSig := sphincs.Spx_sign(params, message, fSk)
		fmt.Print("Looking for signature with matching final node")
		for targetIdxTree != getTreeIdxFromMsg(params, partialFSig.R, pk, message) {
			// pick new keys to forge with in case of not random
			partialFSig = sphincs.Spx_sign(params, message, fSk)
			fSk, _ = sphincs.Spx_keygen(params)
			fmt.Print(".")
		}
		fmt.Println(" Found")

		// see if we can forge the OTS of this message, given our hashCount
		_, otsMsg, _, _ := sphincs.Spx_verify_get_msg_sig_tree(params, message, partialFSig, pk)
		messageBlocks := msgToBaseW(params, otsMsg)

		signable := true
		for i := 0; i < params.Len; i++ {
			if messageBlocks[i] < hashCount[i] {
				signable = false
			}
		}
		if !signable {
			fmt.Println("Message was not signable with our recovered smallest signature :(")
			continue
		}

		fmt.Println("Attempting to forge")
		// create forgery
		forgedSignature := partialFSig
		fWotsSig := forgeOTSignature(params, hashCount, messageBlocks, smallestSignature, pk.PKseed, targetIdxTree)
		forgedSignature.SIG_HT.XMSSSignatures[16].WotsSignature = fWotsSig
		forgedSignature.SIG_HT.XMSSSignatures[16].AUTH = goodSignature.SIG_HT.XMSSSignatures[16].AUTH

		// verify forgery signs
		if sphincs.Spx_verify(params, message, partialFSig, pk) {
			fmt.Println("Forged signature!!!!")
			return forgedSignature
		} else {
			fmt.Println("Failed to forge when should have been successful")
		}

	}
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
