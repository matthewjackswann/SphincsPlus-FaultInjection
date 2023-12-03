package xmss

import (
	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/wots"
	"math"
)

func Xmss_sign_debug(params *parameters.Parameters, M []byte, SKseed []byte, idx int, PKseed []byte, adrs *address.ADRS) *XMSSSignature {
	AUTH := make([]byte, params.Hprime*params.N)
	for i := 0; i < params.Hprime; i++ {
		k := int(math.Floor(float64(idx)/math.Pow(2, float64(i)))) ^ 1
		copy(AUTH[i*params.N:], treehash(params, SKseed, k*int(math.Pow(2, float64(i))), i, PKseed, adrs))
	}

	adrs.SetType(address.WOTS_HASH)
	adrs.SetKeyPairAddress(idx)
	sig := wots.Wots_sign_debug(params, M, SKseed, PKseed, adrs)

	return &XMSSSignature{sig, AUTH}
}
