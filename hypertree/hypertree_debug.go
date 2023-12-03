package hypertree

import (
	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/xmss"
)

func Ht_sign_debug(params *parameters.Parameters, M []byte, SKseed []byte, PKseed []byte, idx_tree uint64, idx_leaf int) *HTSignature {
	// init
	adrs := new(address.ADRS)

	// sign
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)
	SIG_tmp := xmss.Xmss_sign(params, M, SKseed, idx_leaf, PKseed, adrs)
	SIG_HT := make([]*xmss.XMSSSignature, 0)
	SIG_HT = append(SIG_HT, SIG_tmp)
	root := xmss.Xmss_pkFromSig(params, idx_leaf, SIG_tmp, M, PKseed, adrs)
	for j := 1; j < params.D; j++ {
		// Set idx_leaf to be the (h / d) least significant bits of idx_tree
		idx_leaf = int(idx_tree % (1 << uint64(params.H/params.D)))
		// Set idx_tree to be the (h - (j + 1) * (h / d)) most significant bits of idx_tree
		idx_tree = idx_tree >> (params.H / params.D)
		adrs.SetLayerAddress(j)
		adrs.SetTreeAddress(idx_tree)
		SIG_tmp = xmss.Xmss_sign_debug(params, root, SKseed, idx_leaf, PKseed, adrs)
		SIG_HT = append(SIG_HT, SIG_tmp)
		if j < params.D-1 {
			root = xmss.Xmss_pkFromSig(params, idx_leaf, SIG_tmp, root, PKseed, adrs)
		}
	}

	return &HTSignature{SIG_HT}
}
