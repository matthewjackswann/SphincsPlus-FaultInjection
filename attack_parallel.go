package main

import (
	"crypto/rand"
	"fmt"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"time"
)

func parallelSubtree() {
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

	// sign correctly until each WOTS public key is recovered
	hashCounts, shortestHashChains, wotsPublicKeys, authPaths :=
		getPublicKeyChainLengthAndAuthPaths(params, oracleInput, oracleResponse, pk, goodMessage)

	for i := 0; i < 16; i++ {
		fmt.Printf("%x\n", wotsPublicKeys[i][:256])
	}

	// process faults
	shortestHashChains, hashCounts =
		faultySignAndCreateShortestHashChainsParallel(goodMessage, oracleInputFaulty, oracleResponseFaulty, params, pk, hashCounts, shortestHashChains, wotsPublicKeys)

	oracleInput <- nil // stop oracle thread
	time.Sleep(time.Millisecond * 100)

	fmt.Println("We can now sign anything given each block of the message is strictly greater than its respective shortest hash chain")

	// create message to try and forge a signature for
	forgedMessage := make([]byte, params.N)
	_, err = rand.Read(forgedMessage)
	if err != nil {
		panic(err)
	}

	forgedSignature := forgeMessageSignatureParallel(params, forgedMessage, pk, hashCounts, shortestHashChains, authPaths)

	// check our forged message signs. We had no knowledge of sk :)
	if sphincs.Spx_verify(params, forgedMessage, forgedSignature, pk) {
		fmt.Println("It works!!!!")
	} else {
		fmt.Println("Didn't quite work :(")
	}
}

func getPublicKeyChainLengthAndAuthPaths(params *parameters.Parameters, oracleInput chan []byte,
	oracleResponse chan *sphincs.SPHINCS_SIG, pk *sphincs.SPHINCS_PK, message []byte) ([][]int, [][]byte, [][]byte, [][]byte) {

	treesToObserve := 1 << (params.H / params.D)
	hashCounts := make([][]int, treesToObserve)
	shortestHashChains := make([][]byte, treesToObserve)
	wotsPublicKeys := make([][]byte, treesToObserve)
	authPaths := make([][]byte, treesToObserve)

	for treesToObserve > 0 {
		oracleInput <- message
		goodSignature := <-oracleResponse

		lastTreeIdx := getLastTreeIdxFromMsg(params, goodSignature.R, pk, message)
		if len(hashCounts[lastTreeIdx]) != 0 { // if we already have a signature using this subtree skip
			continue
		}

		success, wotsMsg, wotsSig, _ := sphincs.Spx_verify_get_msg_sig_tree(params, message, goodSignature, pk)
		if !success {
			panic("Good signature didn't sign :(")
		}

		shortestHashChains[lastTreeIdx] = wotsSig
		hashCounts[lastTreeIdx] = msgToBaseW(params, wotsMsg)
		wotsPublicKeys[lastTreeIdx] = getWOTSPKFromMessageAndSignature(params, wotsSig, wotsMsg, pk.PKseed, int(lastTreeIdx))
		authPaths[lastTreeIdx] = goodSignature.SIG_HT.XMSSSignatures[params.D-1].AUTH

		treesToObserve -= 1
	}

	return hashCounts, shortestHashChains, wotsPublicKeys, authPaths
}

func faultySignAndCreateShortestHashChainsParallel(
	message []byte, oracleInputFaulty chan []byte, oracleResponseFaulty chan *sphincs.SPHINCS_SIG,
	params *parameters.Parameters, pk *sphincs.SPHINCS_PK,
	hashCounts [][]int, shortestHashChains, wotsPublicKeys [][]byte) ([][]byte, [][]int) {

	userInput := waitForUserInput()
	searching := true
	for searching { // keep looping until the user presses enter
		select {
		case <-userInput:
			searching = false // if user has entered input stop
		default:
			// sign the same message but cause a fault
			oracleInputFaulty <- message
			badSignature := <-oracleResponseFaulty
			badWotsSignature := badSignature.SIG_HT.GetXMSSSignature(params.D - 1).WotsSignature

			idxTree := getLastTreeIdxFromMsg(params, badSignature.R, pk, message)

			// try to recreate message from signature
			success, faultyMessage := getWOTSMessageFromSignatureAndPK(badWotsSignature, wotsPublicKeys[idxTree], params, pk.PKseed, int(idxTree))
			if !success {
				fmt.Println(idxTree)
				panic("Can't recreate message with fault from sig on target tree. This should never happen.")
			}

			smaller := false
			for block := 0; block < params.Len; block++ {
				// if a sig with fewer hashes of a WOTS sk is found, update the shortest hash chain
				if hashCounts[idxTree][block] > faultyMessage[block] {
					smaller = true
					copy(shortestHashChains[idxTree][block*params.N:(block+1)*params.N], badWotsSignature[block*params.N:(block+1)*params.N])
					hashCounts[idxTree][block] = faultyMessage[block]
				}
			}

			if smaller {
				fmt.Println("New shortest set of hash chains: ")
				printIntArrayPadded(hashCounts[idxTree])
			} else {
				fmt.Println("New non-smaller set of hash chains found")
			}

		}
	}

	return shortestHashChains, hashCounts
}

func forgeMessageSignatureParallel(params *parameters.Parameters, message []byte, pk *sphincs.SPHINCS_PK,
	hashCounts [][]int, smallestSignatures, authPaths [][]byte) *sphincs.SPHINCS_SIG {

	for {
		// key pair used to create hypertree to forge signature with
		fSk, _ := sphincs.Spx_keygen(params)
		partialFSig := sphincs.Spx_sign(params, message, fSk)
		tree := getLastTreeIdxFromMsg(params, partialFSig.R, pk, message)

		// see if we can forge the WOTS of this message, given our hashCount
		_, wotsMsg, _, _ := sphincs.Spx_verify_get_msg_sig_tree(params, message, partialFSig, pk)
		messageBlocks := msgToBaseW(params, wotsMsg)

		signable := true
		for i := 0; i < params.Len; i++ {
			if messageBlocks[i] < hashCounts[tree][i] {
				signable = false
			}
		}
		if !signable {
			fmt.Println("Message was not signable with our recovered shortest hash chain length :(")
			printHashCountVsMessageBlocks(messageBlocks, hashCounts[tree])
			continue
		}

		fmt.Println("Attempting to forge with required chain lengths:")
		printIntArrayPadded(messageBlocks)
		fmt.Println("Each of which is greater than or equal to the shortest chain lengths:")
		printIntArrayPadded(hashCounts[tree])
		// create forgery
		forgedSignature := partialFSig
		fWotsSig := forgeOTSignature(params, hashCounts[tree], messageBlocks, smallestSignatures[tree], pk.PKseed, tree)
		forgedSignature.SIG_HT.XMSSSignatures[params.D-1].WotsSignature = fWotsSig
		forgedSignature.SIG_HT.XMSSSignatures[params.D-1].AUTH = authPaths[tree]

		// verify forgery signs
		if sphincs.Spx_verify(params, message, partialFSig, pk) {
			fmt.Println("Forged signature!!!!")
			return forgedSignature
		} else {
			fmt.Println("Failed to forge when should have been successful")
		}

	}
}
