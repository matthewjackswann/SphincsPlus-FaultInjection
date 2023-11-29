package sphincs

import (
	"crypto/rand"
	"fmt"
	"math"

	"github.com/kasperdi/SPHINCSPLUS-golang/address"
	"github.com/kasperdi/SPHINCSPLUS-golang/fors"
	"github.com/kasperdi/SPHINCSPLUS-golang/hypertree"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/util"
)

type SPHINCS_PK struct {
	PKseed []byte
	PKroot []byte
}

type SPHINCS_SK struct {
	SKseed []byte
	SKprf  []byte
	PKseed []byte
	PKroot []byte
}

type SPHINCS_SIG struct {
	R        []byte
	SIG_FORS *fors.FORSSignature
	SIG_HT   *hypertree.HTSignature
}

func (s *SPHINCS_SIG) GetR() []byte {
	return s.R
}

func (s *SPHINCS_SIG) GetSIG_FORS() *fors.FORSSignature {
	return s.SIG_FORS
}

func (s *SPHINCS_SIG) GetSIG_HT() *hypertree.HTSignature {
	return s.SIG_HT
}

func Spx_keygen(params *parameters.Parameters) (*SPHINCS_SK, *SPHINCS_PK) {
	SKseed := make([]byte, params.N)
	rand.Read(SKseed)

	SKprf := make([]byte, params.N)
	rand.Read(SKprf)

	PKseed := make([]byte, params.N)
	rand.Read(PKseed)

	fmt.Println("Waring, using set seed pk and sks")

	SKseed = []byte{98, 7, 181, 163, 174, 11, 8, 141, 215, 234, 95, 11, 247, 30, 142, 217, 195, 61, 180, 170, 46, 1, 233, 140, 201, 77, 210, 201, 62, 157, 239, 126}
	SKprf = []byte{67, 127, 138, 62, 195, 247, 131, 216, 143, 83, 67, 55, 247, 170, 198, 54, 241, 202, 37, 112, 89, 185, 192, 187, 101, 115, 149, 255, 78, 141, 193, 86}
	PKseed = []byte{69, 133, 108, 254, 185, 201, 109, 59, 125, 206, 244, 15, 7, 215, 156, 160, 62, 5, 166, 233, 114, 170, 55, 172, 141, 119, 125, 106, 44, 251, 254, 99}

	PKroot := hypertree.Ht_PKgen(params, SKseed, PKseed)

	sk := new(SPHINCS_SK)
	sk.SKseed = SKseed
	sk.SKprf = SKprf
	sk.PKseed = PKseed
	sk.PKroot = PKroot

	pk := new(SPHINCS_PK)
	pk.PKseed = PKseed
	pk.PKroot = PKroot

	return sk, pk
}

func Spx_sign(params *parameters.Parameters, M []byte, SK *SPHINCS_SK) *SPHINCS_SIG {
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
	SIG.SIG_HT = hypertree.Ht_sign(params, PK_FORS, SKseed, PKseed, idx_tree, idx_leaf)

	return SIG
}

func Spx_verify(params *parameters.Parameters, M []byte, SIG *SPHINCS_SIG, PK *SPHINCS_PK) bool {
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

	return hypertree.Ht_verify(params, PK_FORS, SIG_HT, PKseed, idx_tree, idx_leaf, PKroot)
}
