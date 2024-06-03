package main

import (
	"crypto/rand"
	"fmt"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"time"
)

func singleSubtree() {
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

	shortestHashChains, hashCount, targetIdxTree :=
		faultySignAndCreateShortestHashChains(goodMessage, goodSignature, oracleInputFaulty, oracleResponseFaulty, params, pk)

	oracleInput <- nil // stop oracle thread
	time.Sleep(time.Millisecond * 100)

	fmt.Println("We can now sign anything given each block of the message is strictly greater than: ")
	printIntArrayPadded(hashCount)
	fmt.Printf("The corresponding smallest hash chain lengths are: %x...\n\n", shortestHashChains[:256])

	// create message to try and forge a signature for
	forgedMessage := make([]byte, params.N)
	_, err = rand.Read(forgedMessage)
	if err != nil {
		panic(err)
	}

	forgedSignature := forgeMessageSignature(params, forgedMessage, pk, targetIdxTree, goodSignature, hashCount, shortestHashChains)

	// check our forged message signs. We had no knowledge of sk :)
	if sphincs.Spx_verify(params, forgedMessage, forgedSignature, pk) {
		fmt.Println("It works!!!!")
	} else {
		fmt.Println("Didn't quite work :(")
	}

}

func faultySignAndCreateShortestHashChains(
	goodMessage []byte, goodSignature *sphincs.SPHINCS_SIG, oracleInputFaulty chan []byte, oracleResponseFaulty chan *sphincs.SPHINCS_SIG,
	params *parameters.Parameters, pk *sphincs.SPHINCS_PK) ([]byte, []int, uint64) {

	fmt.Println("Signing faulty messages. Press enter to stop")
	success, wotsMsg, wotsSig, tree := sphincs.Spx_verify_get_msg_sig_tree(params, goodMessage, goodSignature, pk)
	if !success {
		panic("Good signature didn't sign :(")
	}

	targetIdxTree := tree
	for j := 1; j < params.D-1; j++ {
		targetIdxTree = targetIdxTree >> (params.H / params.D)
	}

	// maintain list of the fewest times hashed sk and how many times it was hashed
	shortestHashChains := make([]byte, len(wotsSig))
	copy(shortestHashChains, wotsSig)
	hashCount := msgToBaseW(params, wotsMsg)

	wotsPk := getWOTSPKFromMessageAndSignature(params, wotsSig, wotsMsg, pk.PKseed, tree)

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

			if targetIdxTree != getTreeIdxFromMsg(params, badSig.R, pk, goodMessage) {
				continue
			}

			// try to recreate message from signature
			success, faultyMessage := getWOTSMessageFromSignatureAndPK(badWotsSig, wotsPk, params, pk.PKseed, tree)
			if !success {
				panic("Can't recreate message with fault from sig on target tree. This should never happen.")
			}

			smaller := false
			for block := 0; block < params.Len; block++ {
				// if a sig with fewer hashes of a WOTS sk is found, update the shortest hash chain
				if hashCount[block] > faultyMessage[block] {
					smaller = true
					copy(shortestHashChains[block*params.N:(block+1)*params.N], badWotsSig[block*params.N:(block+1)*params.N])
					hashCount[block] = faultyMessage[block]
				}
			}

			if smaller {
				fmt.Println("New shortest set of hash chains: ")
				printIntArrayPadded(hashCount)
			} else {
				fmt.Println("New non-smaller set of hash chains found")
			}

		}
	}

	return shortestHashChains, hashCount, targetIdxTree
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

		// see if we can forge the WOTS of this message, given our hashCount
		_, wotsMsg, _, _ := sphincs.Spx_verify_get_msg_sig_tree(params, message, partialFSig, pk)
		messageBlocks := msgToBaseW(params, wotsMsg)

		signable := true
		for i := 0; i < params.Len; i++ {
			if messageBlocks[i] < hashCount[i] {
				signable = false
			}
		}
		if !signable {
			fmt.Println("Message was not signable with our recovered shortest hash chain length :(")
			printHashCountVsMessageBlocks(messageBlocks, hashCount)
			continue
		}

		fmt.Println("Attempting to forge with required chain lengths:")
		printIntArrayPadded(messageBlocks)
		fmt.Println("Each of which is greater than or equal to the shortest chail lengths:")
		printIntArrayPadded(hashCount)
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

func singleSubtreeStats() {
	userInput := waitForUserInput()
	looping := true
	for looping {
		select {
		case <-userInput:
			looping = false
		default:
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

			// create message to try and forge a signature for
			forgedMessage := make([]byte, params.N)
			_, err = rand.Read(forgedMessage)
			if err != nil {
				panic(err)
			}

			faultySigsRequired :=
				findRequiredSignatureNumber(goodMessage, goodSignature, oracleInputFaulty, oracleResponseFaulty, params, pk, forgedMessage)

			oracleInput <- nil // stop oracle thread

			fmt.Printf("%d faulty signatures required\n", faultySigsRequired)
			appendToFile("singleNodeFaultyRequires.csv", fmt.Sprintf("%d", faultySigsRequired))
		}
	}
}

func findRequiredSignatureNumber(
	goodMessage []byte, goodSignature *sphincs.SPHINCS_SIG, oracleInputFaulty chan []byte, oracleResponseFaulty chan *sphincs.SPHINCS_SIG,
	params *parameters.Parameters, pk *sphincs.SPHINCS_PK, forgedMessage []byte) int {

	success, wotsMsg, wotsSig, tree := sphincs.Spx_verify_get_msg_sig_tree(params, goodMessage, goodSignature, pk)
	if !success {
		panic("Good signature didn't sign :(")
	}

	targetIdxTree := tree
	for j := 1; j < params.D-1; j++ {
		targetIdxTree = targetIdxTree >> (params.H / params.D)
	}

	// key pair used to create hypertree to forge signature with
	fSk, _ := sphincs.Spx_keygen(params)
	// check partialFSig signed with pk last tree_idx is the same as with signing with fPk
	partialFSig := sphincs.Spx_sign(params, forgedMessage, fSk)
	for targetIdxTree != getTreeIdxFromMsg(params, partialFSig.R, pk, forgedMessage) {
		// pick new keys to forge with in case of not random
		partialFSig = sphincs.Spx_sign(params, forgedMessage, fSk)
		fSk, _ = sphincs.Spx_keygen(params)
	}

	// maintain list of the fewest times hashed sk and how many times it was hashed
	shortestHashChains := make([]byte, len(wotsSig))
	copy(shortestHashChains, wotsSig)
	hashCount := msgToBaseW(params, wotsMsg)

	wotsPk := getWOTSPKFromMessageAndSignature(params, wotsSig, wotsMsg, pk.PKseed, tree)

	for i := 1; i <= 2000; i++ { // keep looping until max 2000 sigs tried or the forgery succeeds
		// sign the same message but cause a fault
		oracleInputFaulty <- goodMessage
		badSig := <-oracleResponseFaulty
		badWotsSig := badSig.SIG_HT.GetXMSSSignature(16).WotsSignature

		if targetIdxTree != getTreeIdxFromMsg(params, badSig.R, pk, goodMessage) {
			continue
		}

		// try to recreate message from signature
		success, faultyMessage := getWOTSMessageFromSignatureAndPK(badWotsSig, wotsPk, params, pk.PKseed, tree)
		if !success {
			panic("Can't recreate message with fault from sig on target tree. This should never happen.")
		}

		smaller := false
		for block := 0; block < params.Len; block++ {
			// if a sig with fewer hashes of a WOTS sk is found, update the shortest hash chain
			if hashCount[block] > faultyMessage[block] {
				smaller = true
				copy(shortestHashChains[block*params.N:(block+1)*params.N], badWotsSig[block*params.N:(block+1)*params.N])
				hashCount[block] = faultyMessage[block]
			}
		}

		if smaller {
			forgeable := checkMessageForgeable(params, forgedMessage, pk, partialFSig, hashCount)
			if forgeable {
				return i
			}
		}
	}
	return -1
}

func checkMessageForgeable(params *parameters.Parameters, message []byte, pk *sphincs.SPHINCS_PK,
	partialFSig *sphincs.SPHINCS_SIG, hashCount []int) bool {

	// see if we can forge the WOTS of this message, given our hashCount
	_, wotsMsg, _, _ := sphincs.Spx_verify_get_msg_sig_tree(params, message, partialFSig, pk)
	messageBlocks := msgToBaseW(params, wotsMsg)

	signable := true
	for i := 0; i < params.Len; i++ {
		if messageBlocks[i] < hashCount[i] {
			signable = false
		}
	}

	printHashCountVsMessageBlocks(messageBlocks, hashCount)
	fmt.Println()

	return signable
}
