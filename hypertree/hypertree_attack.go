package hypertree

import (
	"bytes"
	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/xmss"
)

func Ht_verify_get_msg_sig(params *parameters.Parameters, M []byte, SIG_HT *HTSignature, PKseed []byte, idx_tree uint64, idx_leaf int, PK_HT []byte) (bool, []byte, []byte) {
	// init
	adrs := new(address.ADRS)

	// verify
	SIG_tmp := SIG_HT.GetXMSSSignature(0)
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)
	node := xmss.Xmss_pkFromSig(params, idx_leaf, SIG_tmp, M, PKseed, adrs)

	var msg []byte
	var sig []byte

	for j := 1; j < params.D; j++ {
		idx_leaf = int(idx_tree % (1 << uint64(params.H/params.D)))
		idx_tree = idx_tree >> (params.H / params.D)
		SIG_tmp = SIG_HT.GetXMSSSignature(j)
		adrs.SetLayerAddress(j)
		adrs.SetTreeAddress(idx_tree)
		sig = SIG_tmp.GetWOTSSig()
		msg = node
		node = xmss.Xmss_pkFromSig(params, idx_leaf, SIG_tmp, node, PKseed, adrs)
	}

	return bytes.Equal(node, PK_HT), msg, sig
}
