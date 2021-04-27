package tweakable

import (
    "crypto/sha256"
    "crypto/hmac"
    "math"
    "../util"
    "../address"
    "../parameters"
)

type Sha256Tweak struct {
    Variant string
}

// Tweakable hash function Hmsg
func (h *Sha256Tweak) Hmsg(R []byte, PKseed []byte, PKroot []byte, M []byte) []byte {
    md_len := int(math.Floor((parameters.K * parameters.LogT + 7) / 8))
    idx_tree_len := int(math.Floor((parameters.H - parameters.H / parameters.D + 7) / 8))
    idx_leaf_len := int(math.Floor(parameters.H / parameters.D + 7) / 8)

    m := md_len + idx_tree_len + idx_leaf_len

    hash := sha256.New()
    hash.Write(R)
    hash.Write(PKseed)
    hash.Write(PKroot)
    hash.Write(M)
    hashedConc := hash.Sum(nil)
    bitmask := mgf1sha256(hashedConc, m)
    return bitmask
}

// Tweakable hash function PRF
func (h *Sha256Tweak) PRF(SEED []byte, adrs *address.ADRS) []byte {
    compressedADRS := compressADRS(adrs)
    hash := sha256.New()
    hash.Write(SEED)
    hash.Write(compressedADRS)
    return hash.Sum(nil)
}

// Tweakable hash function PRFmsg
func (h *Sha256Tweak) PRFmsg(SKprf []byte, OptRand []byte, M []byte) []byte {
    mac := hmac.New(sha256.New, SKprf)
    mac.Write(OptRand)
    mac.Write(M)
    return mac.Sum(nil)
}

// Tweakable hash function F
func (h *Sha256Tweak) F(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
    M1 := make([]byte, len(tmp))
    compressedADRS := compressADRS(adrs)

    if h.Variant == Robust {
        bitmask := mgf1sha256(append(PKseed, compressedADRS...), len(tmp))
        M1 = util.XorBytes(tmp, bitmask) 
    } else if h.Variant == Simple {
        M1 = tmp
    }
    
    bytes := make([]byte, 64-parameters.N)
    
    hash := sha256.New()
    hash.Write(PKseed)
    hash.Write(bytes)
    hash.Write(compressedADRS)
    hash.Write(M1)
    return hash.Sum(nil)
}

// Tweakable hash function H
func (h *Sha256Tweak) H(PKseed []byte, adrs *address.ADRS, tmp []byte) []byte {
    return h.F(PKseed, adrs, tmp)
}

// Tweakable hash function T_l
func (h *Sha256Tweak) T_l(PKseed []byte, adrs *address.ADRS , tmp []byte) []byte {
    return h.F(PKseed, adrs, tmp)
}

 // Compresses ADRS into 22 bytes
func compressADRS(adrs *address.ADRS) []byte {
    ADRSc := make([]byte, 22)

    copy(ADRSc[0:1], adrs.LayerAddress[3:4])
    copy(ADRSc[1:9], adrs.TreeAddress[4:12])
    copy(ADRSc[9:10], adrs.Type[3:4])

    switch adrs.GetType() {
    case address.WOTS_HASH:
        copy(ADRSc[10:14], adrs.KeyPairAddress[:])
        copy(ADRSc[14:18], adrs.ChainAddress[:])
        copy(ADRSc[18:22], adrs.HashAddress[:])
    case address.WOTS_PK:
        copy(ADRSc[10:14], adrs.KeyPairAddress[:])
        copy(ADRSc[14:18], make([]byte, 4))
        copy(ADRSc[18:22], make([]byte, 4))
    case address.TREE:
        copy(ADRSc[10:14], make([]byte, 4))
        copy(ADRSc[14:18], adrs.TreeHeight[:])
        copy(ADRSc[18:22], adrs.TreeIndex[:])
    case address.FORS_TREE:
        copy(ADRSc[10:14], adrs.KeyPairAddress[:])
        copy(ADRSc[14:18], adrs.TreeHeight[:])
        copy(ADRSc[18:22], adrs.TreeIndex[:])
    case address.FORS_ROOTS:
        copy(ADRSc[10:14], adrs.KeyPairAddress[:])
        copy(ADRSc[14:18], make([]byte, 4))
        copy(ADRSc[18:22], make([]byte, 4))
    }

    return ADRSc
}

// Based on https://en.wikipedia.org/wiki/Mask_generation_function
func mgf1sha256(seed []byte, length int) []byte {
    T := make([]byte, 0)
    counter := 0
    for len(T) < length {
		C := util.ToByte(uint32(counter), 4) //i2osp equivalent to ToByte
        hash := sha256.New()
        hash.Write(seed)
        hash.Write(C)
        hashedZC := hash.Sum(nil)
        T = append(T, hashedZC...)
        counter++
	}
    // Extract the leading l octets of T as the octet string mask.
    return T[:length]
}