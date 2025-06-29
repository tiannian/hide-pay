package builder

import (
	"fmt"
	"hide-pay/circuits"
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
)

type UTXO struct {
	Nullifier   []circuits.Nullifier
	MerkleProof []MerkleProof

	Commitment              []circuits.Commitment
	EphemeralViewSecretKey  []big.Int
	EphemeralAuditSecretKey []big.Int

	ViewPublicKey  twistededwardbn254.PointAffine
	AuditPublicKey twistededwardbn254.PointAffine
}

func (utxo *UTXO) ToGadget(allAsset []frontend.Variable) (*circuits.UTXOGadget, error) {
	nullifiers := make([]circuits.NullifierGadget, len(utxo.Nullifier))
	merkleProofPath := make([]frontend.Variable, 0)
	merkleProofIndex := make([]frontend.Variable, len(utxo.MerkleProof))

	commitments := make([]circuits.CommitmentGadget, len(utxo.Commitment))

	for i := range utxo.Nullifier {
		nullifiers[i] = *utxo.Nullifier[i].ToGadget()

		merkleProof := utxo.MerkleProof[i].ToGadget()

		merkleProofPath = append(merkleProofPath, merkleProof.Path...)
		merkleProofIndex[i] = merkleProof.Leaf
	}

	for i := range utxo.Commitment {
		commitments[i] = *utxo.Commitment[i].ToGadget()
	}

	ephemeralViewSecretKeys := make([]frontend.Variable, len(utxo.EphemeralViewSecretKey))
	ephemeralAuditSecretKeys := make([]frontend.Variable, len(utxo.EphemeralAuditSecretKey))

	for i := range utxo.EphemeralViewSecretKey {
		ephemeralViewSecretKeys[i] = utxo.EphemeralViewSecretKey[i]
	}

	for i := range utxo.EphemeralAuditSecretKey {
		ephemeralAuditSecretKeys[i] = utxo.EphemeralAuditSecretKey[i]
	}

	receiverPublicKey := [2]frontend.Variable{
		utxo.ViewPublicKey.X,
		utxo.ViewPublicKey.Y,
	}

	auditPublicKey := [2]frontend.Variable{
		utxo.AuditPublicKey.X,
		utxo.AuditPublicKey.Y,
	}

	return &circuits.UTXOGadget{
		AllAsset:                allAsset,
		Nullifier:               nullifiers,
		Commitment:              commitments,
		EphemeralViewSecretKey:  ephemeralViewSecretKeys,
		EphemeralAuditSecretKey: ephemeralAuditSecretKeys,
		ViewPublicKey:           receiverPublicKey,
		AuditPublicKey:          auditPublicKey,
		MerkleProofPath:         merkleProofPath,
		MerkleProofIndex:        merkleProofIndex,
	}, nil
}

func addToAssetMapping(assetMapping map[fr.Element]*fr.Element, asset fr.Element, amount fr.Element) {
	if _, ok := assetMapping[asset]; !ok {
		assetMapping[asset] = &amount
	} else {
		assetMapping[asset].Add(assetMapping[asset], &amount)
	}
}

func (utxo *UTXO) BuildAndCheck() (*UTXOResult, error) {
	nullifiers := make([]fr.Element, len(utxo.Nullifier))
	commitments := make([]UTXOCommitment, len(utxo.Commitment))

	allAssetInput := make(map[fr.Element]*fr.Element)

	currentRoot := fr.NewElement(0)

	for i := range utxo.Nullifier {
		utxoNullifier := utxo.Nullifier[i]

		// zero := fr.NewElement(0)
		// if utxoNullifier.Amount.Cmp(&zero) != 1 {
		// 	return nil, fmt.Errorf("nullifier must be greater than 0")
		// }

		addToAssetMapping(allAssetInput, utxoNullifier.Asset, utxoNullifier.Amount)

		nullifiers[i] = utxoNullifier.Compute()

		merkleProof := utxo.MerkleProof[i]
		merkleRoot := merkleProof.Verify()

		if currentRoot.IsZero() {
			currentRoot = merkleRoot
		} else {
			if currentRoot.Cmp(&merkleRoot) != 0 {
				return nil, fmt.Errorf("merkle root mismatch")
			}
		}
	}

	result := UTXOResult{
		Nullifiers:  nullifiers,
		Commitments: commitments,
		Root:        currentRoot,
	}

	allAssetOutput := make(map[fr.Element]*fr.Element)

	for i := range utxo.Commitment {
		utxoCommitment := utxo.Commitment[i]

		zero := fr.NewElement(0)
		if utxoCommitment.Amount.Cmp(&zero) != 1 {
			return nil, fmt.Errorf("commitment must be greater than 0")
		}

		addToAssetMapping(allAssetOutput, utxoCommitment.Asset, utxoCommitment.Amount)

		commitment := utxoCommitment.Compute()

		ownerMemo := circuits.Memo{
			SecretKey: utxo.EphemeralViewSecretKey[i],
			PublicKey: utxo.ViewPublicKey,
		}

		ownerMemoEphemeralPublickKey, ownerMemoCiphertext, err := ownerMemo.Encrypt(utxoCommitment)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt owner memo: %w", err)
		}

		ownerMemoData := [3]fr.Element{
			ownerMemoCiphertext[0],
			ownerMemoCiphertext[1],
			ownerMemoCiphertext[2],
		}
		ownerHMAC := ownerMemoCiphertext[3]

		auditMemo := circuits.Memo{
			SecretKey: utxo.EphemeralAuditSecretKey[i],
			PublicKey: utxo.AuditPublicKey,
		}

		auditMemoEphemeralPublickKey, auditMemoCiphertext, err := auditMemo.Encrypt(utxoCommitment)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt audit memo: %w", err)
		}

		auditMemoData := [3]fr.Element{
			auditMemoCiphertext[0],
			auditMemoCiphertext[1],
			auditMemoCiphertext[2],
		}
		auditHMAC := auditMemoCiphertext[3]

		commitments[i] = UTXOCommitment{
			Commitment:               commitment,
			OwnerMemo:                ownerMemoData,
			OwnerHMAC:                ownerHMAC,
			OwnerEphemeralPublickKey: *ownerMemoEphemeralPublickKey,
			AuditMemo:                auditMemoData,
			AuditHMAC:                auditHMAC,
			AuditEphemeralPublickKey: *auditMemoEphemeralPublickKey,
		}
	}

	if !reflect.DeepEqual(allAssetInput, allAssetOutput) {
		return nil, fmt.Errorf("input and output asset mapping must be the same")
	}

	for asset := range allAssetInput {
		result.AllAsset = append(result.AllAsset, asset)
	}

	return &result, nil
}

func NewUTXOCircuitWitness(utxo *UTXO, utxoResult *UTXOResult) (*circuits.UTXOCircuit, error) {
	allAsset := make([]frontend.Variable, len(utxoResult.AllAsset))

	for i := range utxoResult.AllAsset {
		allAsset[i] = utxoResult.AllAsset[i]
	}

	utxoGadget, err := utxo.ToGadget(allAsset)
	if err != nil {
		return nil, fmt.Errorf("failed to convert UTXO to gadget: %w", err)
	}

	return &circuits.UTXOCircuit{
		UTXO:   *utxoGadget,
		Result: *utxoResult.ToGadget(),
	}, nil
}
