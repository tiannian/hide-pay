package circuits

import (
	"fmt"
	"hide-pay/utils"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

type UTXOGadget struct {
	AllAsset []frontend.Variable `gnark:"allAsset"`

	Nullifier        []NullifierGadget   `gnark:"nullifier"`
	MerkleProofPath  []frontend.Variable `gnark:"merkleProofPath"`
	MerkleProofIndex []frontend.Variable `gnark:"merkleProofIndex"`

	Commitment []CommitmentGadget `gnark:"commitment"`

	EphemeralViewSecretKey  []frontend.Variable  `gnark:"ephemeralViewSecretKey"`
	EphemeralAuditSecretKey []frontend.Variable  `gnark:"ephemeralAuditSecretKey"`
	ViewPublicKey           [2]frontend.Variable `gnark:"viewPublicKey"`
	AuditPublicKey          [2]frontend.Variable `gnark:"auditPublicKey"`
}

func NewUTXOGadget(allAssetSize int, depth int, nullifierSize int, commitmentSize int) *UTXOGadget {
	return &UTXOGadget{
		AllAsset: make([]frontend.Variable, allAssetSize),

		Nullifier:        make([]NullifierGadget, nullifierSize),
		MerkleProofPath:  make([]frontend.Variable, nullifierSize*depth),
		MerkleProofIndex: make([]frontend.Variable, nullifierSize),

		Commitment:              make([]CommitmentGadget, commitmentSize),
		EphemeralViewSecretKey:  make([]frontend.Variable, commitmentSize),
		EphemeralAuditSecretKey: make([]frontend.Variable, commitmentSize),
	}
}

func (gadget *UTXOGadget) BuildAndCheck(api frontend.API) (*UTXOResultGadget, error) {
	nullifiers := make([]frontend.Variable, len(gadget.Nullifier))
	commitments := make([]frontend.Variable, len(gadget.Commitment))

	// Check that the number of nullifiers, commitments, and ephemeral secret keys are the same
	if len(gadget.Commitment) != len(gadget.EphemeralViewSecretKey) || len(gadget.Commitment) != len(gadget.EphemeralAuditSecretKey) {
		return nil, fmt.Errorf("number of nullifiers, commitments, and ephemeral receiver and audit secret keys must be the same")
	}

	inputAmounts := make([]frontend.Variable, len(gadget.AllAsset))

	for i := range gadget.AllAsset {
		inputAmounts[i] = 0
	}

	merkleRoot := make([]frontend.Variable, len(gadget.Nullifier))

	depth := len(gadget.MerkleProofPath) / len(gadget.Nullifier)

	for i := range gadget.Nullifier {
		gadgetNullifier := gadget.Nullifier[i]

		rangerChecker := rangecheck.New(api)
		rangerChecker.Check(gadgetNullifier.Amount, 253)

		hasher, err := utils.NewPoseidonHasher(api)
		if err != nil {
			return nil, fmt.Errorf("failed to create poseidon hasher: %w", err)
		}

		// TODO: Check nullifier is in merkle tree
		merkleProof := MerkleProofGadget{
			Path: gadget.MerkleProofPath[i*depth : (i+1)*depth],
			Leaf: gadget.MerkleProofIndex[i],
		}

		merkleRoot[i] = merkleProof.VerifyProof(api, hasher)

		for j := range gadget.AllAsset {
			diff := api.Sub(gadget.AllAsset[j], gadgetNullifier.Asset)
			isZero := api.IsZero(diff)
			inputAmounts[j] = api.Add(inputAmounts[j], api.Mul(gadgetNullifier.Amount, isZero))
		}

		nullifier, err := gadgetNullifier.Compute(api)
		if err != nil {
			return nil, fmt.Errorf("failed to compute nullifier: %w", err)
		}
		nullifiers[i] = nullifier
	}

	for i := range merkleRoot {
		api.AssertIsEqual(merkleRoot[i], merkleRoot[0])
	}

	ownerMemoHashes := make([]frontend.Variable, len(gadget.EphemeralViewSecretKey))
	auditMemoHashes := make([]frontend.Variable, len(gadget.EphemeralAuditSecretKey))

	outputAmounts := make([]frontend.Variable, len(gadget.AllAsset))

	for i := range gadget.AllAsset {
		outputAmounts[i] = 0
	}

	for i := range gadget.Commitment {
		gadgetCommitment := gadget.Commitment[i]

		rangerChecker := rangecheck.New(api)
		rangerChecker.Check(gadgetCommitment.Amount, 253)

		for j := range gadget.AllAsset {
			diff := api.Sub(gadget.AllAsset[j], gadgetCommitment.Asset)
			isZero := api.IsZero(diff)
			outputAmounts[j] = api.Add(outputAmounts[j], api.Mul(gadgetCommitment.Amount, isZero))
		}

		commitment, err := gadgetCommitment.Compute(api)
		if err != nil {
			return nil, fmt.Errorf("failed to compute commitment: %w", err)
		}
		commitments[i] = commitment

		ownerMemoGadget := MemoGadget{
			EphemeralSecretKey: gadget.EphemeralViewSecretKey[i],
			ReceiverPublicKey:  gadget.ViewPublicKey,
		}

		ownerMemoHash, err := ownerMemoGadget.Generate(api, gadgetCommitment)
		if err != nil {
			return nil, fmt.Errorf("failed to generate owner memo: %w", err)
		}
		ownerMemoHashes[i] = ownerMemoHash

		auditMemoGadget := MemoGadget{
			EphemeralSecretKey: gadget.EphemeralAuditSecretKey[i],
			ReceiverPublicKey:  gadget.AuditPublicKey,
		}

		auditMemoHash, err := auditMemoGadget.Generate(api, gadgetCommitment)
		if err != nil {
			return nil, fmt.Errorf("failed to generate audit memo: %w", err)
		}
		auditMemoHashes[i] = auditMemoHash
	}

	for i := range inputAmounts {
		api.AssertIsEqual(inputAmounts[i], outputAmounts[i])
	}

	return &UTXOResultGadget{
		Nullifiers:      nullifiers,
		Commitments:     commitments,
		OwnerMemoHashes: ownerMemoHashes,
		AuditMemoHashes: auditMemoHashes,
		MerkleRoot:      merkleRoot[0],
	}, nil
}
