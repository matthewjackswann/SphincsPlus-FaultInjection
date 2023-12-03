package wots

import (
	"fmt"
	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/util"
	"math"
)

// Signs a message using WOTS+
func Wots_sign_debug(params *parameters.Parameters, message []byte, SKseed []byte, PKseed []byte, adrs *address.ADRS) []byte {
	csum := 0

	// Convert message to base w
	msg := util.Base_w(message, params.W, params.Len1)

	for i := 0; i < params.Len1; i++ {
		csum = csum + params.W - 1 - msg[i]
	}

	// convert csum to base w
	if int(math.Log2(float64(params.W)))%8 != 0 {
		csum = csum << (8 - ((params.Len2 * int(math.Log2(float64(params.W)))) % 8))
	}

	len2_bytes := int(math.Ceil((float64(params.Len2) * math.Log2(float64(params.W))) / 8))
	msg = append(msg, util.Base_w(util.ToByte(uint64(csum), len2_bytes), params.W, params.Len2)...)

	sig := make([]byte, params.Len*params.N)

	sks := make([]byte, 0)

	for i := 0; i < params.Len; i++ {
		adrs.SetChainAddress(i)
		adrs.SetHashAddress(0)
		sk := params.Tweak.PRF(SKseed, adrs)
		sks = append(sks, sk...)
		copy(sig[i*params.N:], chain(params, sk, 0, msg[i], PKseed, adrs))
	}

	if adrs.LayerAddress[3] == 16 {
		fmt.Printf("[Secret] final layer WOTS sk: %x\n", sks)
	}

	return sig
}
