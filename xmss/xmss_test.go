package xmss

import (
	"testing"
	"crypto/rand"
	"bytes"
	"../address"
	"../parameters"
)

// Tests that signed messages can be verified with the correct signature
func TestSignAndVerify(t *testing.T) {
	params := parameters.MakeSphincsPlusSHA256256fRobust(false)
	for i := 0; i < 10; i++ {
		message := make([]byte, params.N)
		rand.Read(message)
		SKseed := make([]byte, params.N)
		rand.Read(SKseed)
		PKseed := make([]byte, params.N)
		rand.Read(SKseed)
		var adrs address.ADRS // Are 3 needed?
		var adrs2 address.ADRS
		var adrs3 address.ADRS

		PK := Xmss_PKgen(params, SKseed, PKseed, &adrs)

		signature := Xmss_sign(params, message, SKseed, 0, PKseed, &adrs2)

		pkFromSig := Xmss_pkFromSig(params, 0, signature, message, PKseed, &adrs3) 
		if(!bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
}

func TestSignVerifyWrongKey(t *testing.T) {
	params := parameters.MakeSphincsPlusSHA256256fRobust(false)
	for i := 1; i < 10; i++ {
		message := make([]byte, params.N)
		rand.Read(message)
		wrongMessage := make([]byte, params.N)
		rand.Read(wrongMessage)
		SKseed := make([]byte, params.N)
		rand.Read(SKseed)
		PKseed := make([]byte, params.N)
		rand.Read(SKseed)
		var adrs address.ADRS // Are 3 needed?
		var adrs2 address.ADRS
		var adrs3 address.ADRS

		PK := Xmss_PKgen(params, SKseed, PKseed, &adrs)

		signature := Xmss_sign(params, message, SKseed, 0, PKseed, &adrs2)

		pkFromSig := Xmss_pkFromSig(params, 0, signature, wrongMessage, PKseed, &adrs3) 
		if(bytes.Equal(pkFromSig, PK)) {
			t.Errorf("Verification of signed message failed, but was expected to succeed!")
		}
	}
	

}