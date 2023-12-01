package hypertree

import (
	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/xmss"
	mathrand "math/rand"
)

func Ht_sign_fault(params *parameters.Parameters, M []byte, SKseed []byte, PKseed []byte, idx_tree uint64, idx_leaf int) *HTSignature {
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

		// cause fault in second to last tree by mutating a bit of root
		if j == params.D-2 {
			fault_b(root)
		}

		SIG_tmp = xmss.Xmss_sign(params, root, SKseed, idx_leaf, PKseed, adrs)

		// cause fault in second to last tree by mutating a bit of SIG_tmp
		//if j == params.D-2 {
		//	fault(SIG_tmp)
		//}

		SIG_HT = append(SIG_HT, SIG_tmp)
		if j < params.D-1 {
			root = xmss.Xmss_pkFromSig(params, idx_leaf, SIG_tmp, root, PKseed, adrs)
		}
	}

	return &HTSignature{SIG_HT}
}

//func fault(SIG_tmp *xmss.XMSSSignature) {
//	//mathrand.Seed(0)
//	//fmt.Println("Seeded fault!!")
//	targetBit := mathrand.Intn(8 * (len(SIG_tmp.AUTH) + len(SIG_tmp.WotsSignature)))
//	if targetBit >= 8*len(SIG_tmp.AUTH) {
//		// flip (targetBit - 8*len(SIG_tmp.AUTH)) bit of SIG_tmp.WotsSignature
//		targetBit -= 8 * len(SIG_tmp.AUTH)
//		SIG_tmp.WotsSignature[targetBit>>3] ^= 1 << (targetBit % 8)
//	} else {
//		// flip targetBit of SIG_tmp.AUTH
//		SIG_tmp.AUTH[targetBit>>3] ^= 1 << (targetBit % 8)
//	}
//}

func fault_b(bits []byte) {
	//mathrand.Seed(0)
	//fmt.Println("Seeded fault!!")
	targetBit := mathrand.Intn(8 * len(bits))
	bits[targetBit>>3] ^= 1 << (targetBit % 8)
}
