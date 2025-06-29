package circuits_test

import (
	"hide-pay/builder"
	"hide-pay/circuits"
	"hide-pay/utils"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

func TestUTXO_ToGadget(t *testing.T) {
	receiverSecretKey := big.NewInt(11111)
	auditSecretKey := big.NewInt(22222)

	receiverPublicKey := utils.BuildPublicKey(*receiverSecretKey)
	auditPublicKey := utils.BuildPublicKey(*auditSecretKey)

	nullifier1 := circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(1),
			Amount:   fr.NewElement(2),
			Blinding: fr.NewElement(3),
		},
	}

	nullifier2 := circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(1),
			Amount:   fr.NewElement(2),
			Blinding: fr.NewElement(4),
		},
	}

	depth := 10

	merkleTree := builder.NewMerkleTree(depth, poseidon2.NewMerkleDamgardHasher())
	elems := []fr.Element{
		nullifier1.Commitment.Compute(),
		nullifier2.Commitment.Compute(),
	}
	merkleTree.Build(elems)
	root := merkleTree.GetRoot()

	merkleProof1 := merkleTree.GetProof(0)
	merkleProof2 := merkleTree.GetProof(1)

	root1 := merkleProof1.Verify()
	root2 := merkleProof2.Verify()

	assert.Equal(t, root, root1)
	assert.Equal(t, root, root2)

	utxo := &builder.UTXO{
		Nullifier: []circuits.Nullifier{
			nullifier1,
			nullifier2,
		},
		MerkleProof: []builder.MerkleProof{
			merkleProof1,
			merkleProof2,
		},
		Commitment: []circuits.Commitment{
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: fr.NewElement(5),
			},
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: fr.NewElement(6),
			},
		},
		EphemeralViewSecretKey: []big.Int{
			*big.NewInt(1),
			*big.NewInt(2),
		},
		EphemeralAuditSecretKey: []big.Int{
			*big.NewInt(3),
			*big.NewInt(4),
		},
		ViewPublicKey:  receiverPublicKey,
		AuditPublicKey: auditPublicKey,
	}

	result, err := utxo.BuildAndCheck()
	assert.NoError(t, err)

	witness, err := builder.NewUTXOCircuitWitness(utxo, result)
	assert.NoError(t, err)

	utxoCircuit := circuits.NewUTXOCircuit(len(result.AllAsset), depth, len(utxo.Nullifier), len(utxo.Commitment))

	assert := test.NewAssert(t)

	assert.ProverSucceeded(utxoCircuit, witness, test.WithCurves(ecc.BN254))
}
