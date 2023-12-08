package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"os"
	"time"
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

	success, ots_msg, ots_sig, tree := sphincs.Spx_verify_get_msg_sig_tree(params, goodMessage, goodSignature, pk)
	if !success {
		panic("Good signature didn't sign :(")
	}

	ots_pk := getWOTSPKFromMessageAndSignature(params, ots_sig, ots_msg, pk.PKseed, tree)

	fmt.Println("Signed message")
	fmt.Println("Signing faulty messages. Press enter to stop")

	// maintain list of the fewest times hashed sk and how many times it was hashed
	smallestSignature := make([]byte, len(ots_sig))
	copy(smallestSignature, ots_sig)
	hashCount := msgToBaseW(params, ots_msg)

	target_idx_tree := tree
	for j := 1; j < params.D-1; j++ {
		target_idx_tree = target_idx_tree >> (params.H / params.D)
	}

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
				this_pk := getWOTSPKFromMessageAndSignatureI(params, smallestSignature, hashCount, pk.PKseed, tree)
				if !bytes.Equal(this_pk, ots_pk) {
					panic("Noooooo")
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

	// create message to try and forge a signature for
	forgedMessage := make([]byte, params.N)
	_, err = rand.Read(forgedMessage)
	if err != nil {
		panic(err)
	}

	target_idx_tree = tree
	for j := 1; j < params.D-1; j++ {
		target_idx_tree = target_idx_tree >> (params.H / params.D)
	}

	for {
		// key pair used to create hypertree to forge signature with
		fSk, _ := sphincs.Spx_keygen(params)
		// check partialFSig signed with pk last tree_idx is the same as with signing with fPk
		partialFSig := sphincs.Spx_sign(params, forgedMessage, fSk)
		fmt.Print("Looking for signature with matching final node")
		for target_idx_tree != getTreeIdxFromMsg(params, partialFSig.R, pk, forgedMessage) {
			// pick new keys to forge with in case of not random
			partialFSig = sphincs.Spx_sign(params, forgedMessage, fSk)
			fSk, _ = sphincs.Spx_keygen(params)
			fmt.Print(".")
		}

		fmt.Println(" Found")

		_, otsMsg, _, _ := sphincs.Spx_verify_get_msg_sig_tree(params, forgedMessage, partialFSig, pk)
		messageBlocks := msgToBaseW(params, otsMsg)

		signable := true
		for i := 0; i < params.Len; i++ {
			if messageBlocks[i] < hashCount[i] {
				signable = false
				break
			}
		}
		if !signable {
			fmt.Println("Message was not singable with our recovered smallest signature :(")
			continue
		}
		fmt.Println("Attempting to forge")
		f_wots_sig := forgeSignature(params, hashCount, messageBlocks, smallestSignature, pk.PKseed, target_idx_tree)
		partialFSig.SIG_HT.XMSSSignatures[16].WotsSignature = f_wots_sig
		partialFSig.SIG_HT.XMSSSignatures[16].AUTH = goodSignature.SIG_HT.XMSSSignatures[16].AUTH

		fmt.Println(sphincs.Spx_verify(params, forgedMessage, partialFSig, pk))

		fmt.Println(sphincs.Spx_verify(params, goodMessage, goodSignature, pk))

		return
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
