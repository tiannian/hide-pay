package builder_test

import (
	"hide-pay/builder"
	"hide-pay/circuits"
	"hide-pay/utils"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/stretchr/testify/assert"
)

func TestUTXO_BuildAndCheck(t *testing.T) {
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
		PrivateKey: fr.NewElement(1),
	}

	nullifier2 := circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(1),
			Amount:   fr.NewElement(2),
			Blinding: fr.NewElement(4),
		},
		PrivateKey: fr.NewElement(2),
	}

	nullifier1_commit := nullifier1.Commitment.Compute()
	nullifier2_commit := nullifier2.Commitment.Compute()

	merkleTree := builder.NewMerkleTree(10, poseidon2.NewMerkleDamgardHasher())
	elems := []fr.Element{
		nullifier1_commit,
		nullifier2_commit,
	}
	merkleTree.Build(elems)

	merkleProof1 := merkleTree.GetProof(0)
	merkleProof2 := merkleTree.GetProof(1)

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
				Blinding: fr.NewElement(3),
			},
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: fr.NewElement(3),
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

	for i := range result.Commitments {
		commitment := result.Commitments[i]

		memo1 := circuits.Memo{
			SecretKey: *receiverSecretKey,
			PublicKey: commitment.OwnerEphemeralPublickKey,
		}

		ownerMemoCiphertext := []fr.Element{
			commitment.OwnerMemo[0],
			commitment.OwnerMemo[1],
			commitment.OwnerMemo[2],
			commitment.OwnerHMAC,
		}

		decryptedOwnerMemo, err := memo1.Decrypt(ownerMemoCiphertext)
		assert.NoError(t, err)
		assert.Equal(t, decryptedOwnerMemo.Asset, utxo.Commitment[i].Asset)
		assert.Equal(t, decryptedOwnerMemo.Amount, utxo.Commitment[i].Amount)
		assert.Equal(t, decryptedOwnerMemo.Blinding, utxo.Commitment[i].Blinding)

		memo2 := circuits.Memo{
			SecretKey: *auditSecretKey,
			PublicKey: commitment.AuditEphemeralPublickKey,
		}

		auditMemoCiphertext := []fr.Element{
			commitment.AuditMemo[0],
			commitment.AuditMemo[1],
			commitment.AuditMemo[2],
			commitment.AuditHMAC,
		}

		decryptedAuditMemo, err := memo2.Decrypt(auditMemoCiphertext)
		assert.NoError(t, err)
		assert.Equal(t, decryptedAuditMemo.Asset, utxo.Commitment[i].Asset)
		assert.Equal(t, decryptedAuditMemo.Amount, utxo.Commitment[i].Amount)
		assert.Equal(t, decryptedAuditMemo.Blinding, utxo.Commitment[i].Blinding)
	}
}
