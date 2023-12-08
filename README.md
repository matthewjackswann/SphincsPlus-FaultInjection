# SphincsPlus-FaultInjection

This project was part of my COMSM0042 - Advanced Cryptology coursework.

It specifically answers the question 
> Write or modify an implementation of SPHINCS+ that can _simulate_ the fault
described in the paper (Practical Fault Injection Attacks on SPHINCS - Aymeric Genêt, Matthias J. Kannwischer, Hervé Pelletier, and Andrew McLauchlan), and implement the processing phase.

by implementing an attack, allowing an adversary to universally forge message signatures (I hope).

This is a fork of [SPHINCSPLUS-golang](https://github.com/kasperdi/SPHINCSPLUS-golang), a pre-existing SPHINCS+ implementation in go

## SPHINCSPLUS-golang

This repository contains an implementation of the SPHINCS<sup>+</sup> signature framework as described in https://sphincs.org/data/sphincs+-round3-specification.pdf.

Test vectors for WOTS<sup>+</sup>, FORS, and SPHINCS<sup>+</sup> can be found in their respective folders. The tests themselves can be found in the Go test files, while the expected signatures can then be found in the expected_signature folders. The test vectors cover the 24 named variants described in the specification that are instantiated using either SHA-256 or SHAKE256. The test that checks if the output matches the expected signature is called testSignFixed, and it is a subtest that is run for each of the named variants.

## Faults
Faults are made by randomly flipping up to 64 bits in the 2nd to last signature while constructing the hyper tree. To better replicate the fault in the paper, the layer in the tree could be randomised; the same attack would still work by only using signatures from the correct layer, but this would be slower for no good reason, so I didn't do it.

## Attack
The attack works be re-using a winternitz one time signature (WOTS). By signing the same message there is a $\frac{1}{16}$ chance that the same $(pk, sk)$ pair will be used for the last layer. If the message a fault occurs then a different message will be signed, breaking the one time usage security requirement.

- First a message is signed without a fault. This allows us to calculate the pk used for the message
- We then repeatability faultily sign messages and see if we can reverse the message from the signature and $sk$.
  - If the message was signed with another $sk'$ then the message can't be reversed, and we try another message.
- If any block of the new signature is hashed less than the current best, we can update that block, effectively moving backwards up the hash chain.
- Once we have made a small enough signature we can sign any message with each block strictly better than the current best. This allows an adversary to create a hypertree and sign it's public key as if it was signed with $sk$. This allows an adversary to sign any message as if they were the owner of the SPHINCS+ public key (which is bad).

## Implementation
`attack.go` contains the main script used for running the attack and `attack_helper.go` contains helper functions for the attack.

Files ending in `_fault` contain a modified version of the original code and simulating a fault occurring during encryption.

Files ending in `_debug` make no changes to the original code except for adding debug statements while correctly signing messages.

The function `createSigningOracle`, creates a signing oracle and returns a public key and channels for communication. This prevents the rest of the program from having access to the secret key used to sign any messages. It ensures that the attack can run with only information gained through interacting with a faulty oracle.

## Usage

The attack can be launched by running:
```
go run attack.go
```
The program will repeatedly test faulty signatures until the user presses `ENTER` on the console.

It will then try and forge a signature for a randomly created message.

## Output

### faultySignAndCreateSmallestSignature
When the program starts it signs a message and outputs the secret key used in the last layer of the hypertree. This is only debug output for showing correctness and isn't accessible during the attack.

When a new smallest signature is found, the number of times each block has been hashed is output to the console.

After enough time the user can press enter to finish searching. The program will
- Stop the oracle thread. This prints the number of time it signed and faultily signed a message
- Print the smallest number of times each block in the smallest signature were hashed.
- Print the smallest signature. If a block was hashed $0$ times then it should correspond with the debug secret key output at the start of the program 

### forgeMessageSignature

The program will then try and create a new hypertree, such that it can be signed using the smallest signature. It re-generates key pairs as non-random variants of SPHINCS+ will consistently fail to verify.

Once a hypertree is found such that it's nodes public key is strictly greater than the minimum number of hashes in each block of the smallest signature, it can be grafted onto an already valid signature.

This is returned and tested to ensure the provided message and generated signature, verify using the public key of the oracle.
