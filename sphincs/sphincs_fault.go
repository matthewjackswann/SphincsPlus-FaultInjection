package sphincs

import (
	"crypto/rand"
	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/fors"
	"github.com/kasperdi/SPHINCSPLUS-golang/hypertree"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/util"
	"math"
)

func Spx_sign_fault(params *parameters.Parameters, M []byte, SK *SPHINCS_SK) *SPHINCS_SIG {
	// init
	adrs := new(address.ADRS)

	// generate randomizer
	opt := make([]byte, params.N)
	if params.RANDOMIZE {
		rand.Read(opt)
	}

	R := params.Tweak.PRFmsg(SK.SKprf, opt, M)

	SIG := new(SPHINCS_SIG)
	SIG.R = R

	// compute message digest and index
	digest := params.Tweak.Hmsg(R, SK.PKseed, SK.PKroot, M)
	tmp_md_bytes := int(math.Floor(float64(params.K*params.A+7) / 8))
	tmp_idx_tree_bytes := int(math.Floor(float64(params.H-params.H/params.D+7) / 8))
	tmp_idx_leaf_bytes := int(math.Floor(float64(params.H/params.D+7)) / 8)

	tmp_md := digest[:tmp_md_bytes]
	tmp_idx_tree := digest[tmp_md_bytes:(tmp_md_bytes + tmp_idx_tree_bytes)]
	tmp_idx_leaf := digest[(tmp_md_bytes + tmp_idx_tree_bytes):(tmp_md_bytes + tmp_idx_tree_bytes + tmp_idx_leaf_bytes)]

	idx_tree := uint64(util.BytesToUint64(tmp_idx_tree) & (math.MaxUint64 >> (64 - (params.H - params.H/params.D))))
	idx_leaf := int(util.BytesToUint32(tmp_idx_leaf) & (math.MaxUint32 >> (32 - params.H/params.D)))

	// FORS sign
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)
	adrs.SetType(address.FORS_TREE)
	adrs.SetKeyPairAddress(idx_leaf)

	// This ensures that we avoid side effects modifying PK
	SKseed := make([]byte, params.N)
	copy(SKseed, SK.SKseed)
	PKseed := make([]byte, params.N)
	copy(PKseed, SK.PKseed)

	SIG.SIG_FORS = fors.Fors_sign(params, tmp_md, SKseed, PKseed, adrs)

	PK_FORS := fors.Fors_pkFromSig(params, SIG.SIG_FORS, tmp_md, PKseed, adrs)

	// sign FORS public key with HT
	adrs.SetType(address.TREE)
	SIG.SIG_HT = hypertree.Ht_sign_fault(params, PK_FORS, SKseed, PKseed, idx_tree, idx_leaf)

	return SIG
}

func Spx_verify_get_msg_sig(params *parameters.Parameters, M []byte, SIG *SPHINCS_SIG, PK *SPHINCS_PK) (bool, []byte, []byte) {
	// init
	adrs := new(address.ADRS)
	R := SIG.GetR()
	SIG_FORS := SIG.GetSIG_FORS()
	SIG_HT := SIG.GetSIG_HT()

	// compute message digest and index
	digest := params.Tweak.Hmsg(R, PK.PKseed, PK.PKroot, M)

	tmp_md_bytes := int(math.Floor(float64(params.K*params.A+7) / 8))
	tmp_idx_tree_bytes := int(math.Floor(float64(params.H-params.H/params.D+7) / 8))
	tmp_idx_leaf_bytes := int(math.Floor(float64(params.H/params.D+7)) / 8)

	tmp_md := digest[:tmp_md_bytes]
	tmp_idx_tree := digest[tmp_md_bytes:(tmp_md_bytes + tmp_idx_tree_bytes)]
	tmp_idx_leaf := digest[(tmp_md_bytes + tmp_idx_tree_bytes):(tmp_md_bytes + tmp_idx_tree_bytes + tmp_idx_leaf_bytes)]

	idx_tree := uint64(util.BytesToUint64(tmp_idx_tree) & (math.MaxUint64 >> (64 - (params.H - params.H/params.D))))
	idx_leaf := int(util.BytesToUint32(tmp_idx_leaf) & (math.MaxUint32 >> (32 - params.H/params.D)))

	// compute FORS public key
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)
	adrs.SetType(address.FORS_TREE)
	adrs.SetKeyPairAddress(idx_leaf)

	// This ensures that we avoid side effects modifying PK
	PKseed := make([]byte, params.N)
	copy(PKseed, PK.PKseed)
	PKroot := make([]byte, params.N)
	copy(PKroot, PK.PKroot)

	PK_FORS := fors.Fors_pkFromSig(params, SIG_FORS, tmp_md, PKseed, adrs)

	// verify HT signature
	adrs.SetType(address.TREE)
	//a, b, c := hypertree.Ht_verify_get_msg_sig(params, PK_FORS, SIG_HT, PKseed, idx_tree, idx_leaf, PKroot)
	return hypertree.Ht_verify_get_msg_sig(params, PK_FORS, SIG_HT, PKseed, idx_tree, idx_leaf, PKroot)
}
