package tweakable

import (
	"testing"
	"encoding/hex"
	"bytes"
	"fmt"
	"../address"
	"../util"
)

// Test of MGF1-SHA256
func TestMgf1Sha256(t *testing.T) { //TODO: MORE TEST CASES, GENERATE DATA USING PYTHON IMPLEMENTATION
	result := hex.EncodeToString(mgf1sha256([]byte("bar"), 50))
	expected := "382576a7841021cc28fc4c0948753fb8312090cea942ea4c4e735d10dc724b155f9f6069f289d61daca0cb814502ef04eae1"
	if (expected != result) {
		t.Errorf("Expected: %s, but got %s", expected, result)
	}
	

}

// Test of ADRS compression ADRSc for ADRS type 0
func TestCompressADRSType0(t *testing.T) {
	
	layerAddress := [4]byte{0, 1, 2, 3}
	treeAddress := [12]byte{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	var typ [4]byte														// This is not very clean, fix maybe?
	copy(typ[:], util.ToByte(uint32(0), 4))								// Type 0 corresponds to a WOTS+ hash address
	keyPairAddress := [4]byte{20, 21, 22, 23}
	chainAddress := [4]byte{24, 25, 26, 27}
	hashAddress := [4]byte{28, 29, 30, 31}

	adrs := address.ADRS{
		LayerAddress: layerAddress,
		TreeAddress: treeAddress,
		Type: typ,
		KeyPairAddress: keyPairAddress,
		ChainAddress: chainAddress,
		HashAddress: hashAddress,
	}
	adrsc := compressADRS(&adrs)
	
	expected := [22]byte{3, 8, 9, 10, 11, 12, 13, 14, 15, 0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	if(!bytes.Equal(adrsc, expected[:])) {
		t.Errorf("Compression of type 0 ADRS did not result in the correct bytes")
		fmt.Println(adrsc)
		fmt.Println(expected[:])
	}
	
}

func TestCompressADRSType1(t *testing.T) {
	
	layerAddress := [4]byte{0, 1, 2, 3}
	treeAddress := [12]byte{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	var typ [4]byte														// This is not very clean, fix maybe?
	copy(typ[:], util.ToByte(uint32(1), 4))								// Type 0 corresponds to a WOTS+ hash address
	keyPairAddress := [4]byte{20, 21, 22, 23}

	adrs := address.ADRS{
		LayerAddress: layerAddress,
		TreeAddress: treeAddress,
		Type: typ,
		KeyPairAddress: keyPairAddress,
	}
	adrsc := compressADRS(&adrs)
	
	expected := [22]byte{3, 8, 9, 10, 11, 12, 13, 14, 15, 1, 20, 21, 22, 23, 0, 0, 0, 0, 0, 0, 0, 0}
	if(!bytes.Equal(adrsc, expected[:])) {
		t.Errorf("Compression of type 0 ADRS did not result in the correct bytes")
		fmt.Println(adrsc)
		fmt.Println(expected[:])
	}
	
	
}