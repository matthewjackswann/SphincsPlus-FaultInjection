package address

import (
	"encoding/binary"
	"../util"
)

const (
	// ADRS types
	WOTS_HASH = 0
	WOTS_PK = 1
	TREE = 2
	FORS_TREE = 3
	FORS_ROOTS = 4
)

type ADRS struct {
    LayerAddress [4]byte
	TreeAddress [12]byte
	Type [4]byte
	KeyPairAddress [4]byte
	TreeHeight [4]byte
	TreeIndex [4]byte
	ChainAddress [4]byte
	HashAddress [4]byte
}

func (adrs *ADRS) Copy() *ADRS {
	newADRS := new(ADRS)
	newADRS.LayerAddress = adrs.LayerAddress
	newADRS.TreeAddress = adrs.TreeAddress
	newADRS.Type = adrs.Type
	newADRS.KeyPairAddress = adrs.KeyPairAddress
	newADRS.TreeHeight = adrs.TreeHeight
	newADRS.TreeIndex = adrs.TreeIndex
	newADRS.ChainAddress = adrs.ChainAddress
	newADRS.HashAddress = adrs.HashAddress
	return newADRS
}

func (adrs *ADRS) GetBytes() []byte {
	ADRSc := make([]byte, 32)

    copy(ADRSc[0:4], adrs.LayerAddress[:])
    copy(ADRSc[4:16], adrs.TreeAddress[:])
    copy(ADRSc[16:20], adrs.Type[:])

    switch adrs.GetType() {
    case WOTS_HASH:
        copy(ADRSc[10:14], adrs.KeyPairAddress[:])
        copy(ADRSc[14:18], adrs.ChainAddress[:])
        copy(ADRSc[18:22], adrs.HashAddress[:])
    case WOTS_PK:
        copy(ADRSc[10:14], adrs.KeyPairAddress[:])
        copy(ADRSc[14:18], make([]byte, 4))
        copy(ADRSc[18:22], make([]byte, 4))
    case TREE:
        copy(ADRSc[10:14], make([]byte, 4))
        copy(ADRSc[14:18], adrs.TreeHeight[:])
        copy(ADRSc[18:22], adrs.TreeIndex[:])
    case FORS_TREE:
        copy(ADRSc[10:14], adrs.KeyPairAddress[:])
        copy(ADRSc[14:18], adrs.TreeHeight[:])
        copy(ADRSc[18:22], adrs.TreeIndex[:])
    case FORS_ROOTS:
        copy(ADRSc[10:14], adrs.KeyPairAddress[:])
        copy(ADRSc[14:18], make([]byte, 4))
        copy(ADRSc[18:22], make([]byte, 4))
    }

    return ADRSc
}

func (adrs *ADRS) SetLayerAddress(a int) { //uint32 eller int
	var layerAddress [4]byte
	copy(layerAddress[:], util.ToByte(uint32(a), 4))	
    adrs.LayerAddress = layerAddress
}

func (adrs *ADRS) SetTreeAddress(a uint64) { //Allow 12 byte ints (big.Int)
	var treeAddress [12]byte //This is not very clean
	treeAddressBytes := util.ToByte3(a, 12)
	copy(treeAddress[:], treeAddressBytes)
    adrs.TreeAddress = treeAddress
}

func (adrs *ADRS) SetType(a int) { //uint32 eller int
	var typ [4]byte
	copy(typ[:], util.ToByte(uint32(a), 4))
    adrs.Type = typ
	//Set the three last words to 0 as described in section 2.7.3
	adrs.SetKeyPairAddress(0)
	adrs.SetChainAddress(0)
	adrs.SetHashAddress(0)
	adrs.SetTreeHeight(0)
	adrs.SetTreeIndex(0)
}

func (adrs *ADRS) SetKeyPairAddress(a int) { //uint32 eller int
	var keyPairAddress [4]byte
	copy(keyPairAddress[:], util.ToByte(uint32(a), 4))
    adrs.KeyPairAddress = keyPairAddress
}

func (adrs *ADRS) SetTreeHeight(a int) { //uint32 eller int
	var treeHeight [4]byte
	copy(treeHeight[:], util.ToByte(uint32(a), 4))
    adrs.TreeHeight = treeHeight
}

func (adrs *ADRS) SetTreeIndex(a int) { //uint32 eller int
	var treeIndex [4]byte
	copy(treeIndex[:], util.ToByte(uint32(a), 4))
    adrs.TreeIndex = treeIndex
}

func (adrs *ADRS) SetChainAddress(a int) { //uint32 eller int
	var chainAddress [4]byte
	copy(chainAddress[:], util.ToByte(uint32(a), 4))
    adrs.ChainAddress = chainAddress
}


func (adrs *ADRS) SetHashAddress(a int) { //uint32 eller int
	var hashAddress [4]byte
	copy(hashAddress[:], util.ToByte(uint32(a), 4))
    adrs.HashAddress = hashAddress
}

func (adrs *ADRS) GetKeyPairAddress() int { //uint32 eller int
	keyPairAddressBytes := adrs.KeyPairAddress[:]
	keyPairAddressUint32 := binary.BigEndian.Uint32(keyPairAddressBytes)
	return int(keyPairAddressUint32)
}

func (adrs *ADRS) GetTreeIndex() int { //uint32 eller int
	treeIndexBytes := adrs.TreeIndex[:]
	treeIndexUint32 := binary.BigEndian.Uint32(treeIndexBytes)
	return int(treeIndexUint32)
}

func (adrs *ADRS) GetTreeHeight() int { //uint32 eller int
	treeHeightBytes := adrs.TreeHeight[:]
	treeHeightUint32 := binary.BigEndian.Uint32(treeHeightBytes)
	return int(treeHeightUint32)
}

func (adrs *ADRS) GetType() int { //uint32 eller int
	typeBytes := adrs.Type[:]
	typeUint32 := binary.BigEndian.Uint32(typeBytes)
	return int(typeUint32)
}

func (adrs *ADRS) GetTreeAddress() int { //uint32 eller int
	treeAddressBytes := adrs.TreeAddress[:]
	treeAddressUint32 := binary.BigEndian.Uint32(treeAddressBytes)
	return int(treeAddressUint32)
}

