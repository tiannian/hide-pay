package builder_test

import (
	"hide-pay/builder"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/stretchr/testify/assert"
)

func TestMerkleTreeBuild(t *testing.T) {
	elems := []fr.Element{
		fr.NewElement(1),
		fr.NewElement(2),
		fr.NewElement(3),
		fr.NewElement(4),
	}

	hasher := poseidon2.NewMerkleDamgardHasher()

	mt := builder.NewMerkleTree(34, hasher)

	for _, elem := range elems {
		mt.AppendSingle(elem)
	}

	proof := mt.GetProof(2)

	proofRoot := proof.Verify()

	merkleRoot := mt.GetRoot()
	assert.Equal(t, proofRoot, merkleRoot)
}
