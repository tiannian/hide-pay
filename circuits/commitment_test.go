package circuits_test

import (
	"fmt"
	"hide-pay/builder"
	"hide-pay/circuits"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

type CommitmentCircuit struct {
	circuits.CommitmentGadget
	Commitment frontend.Variable `gnark:"commitment,public"`
}

func NewCommitmentCircuit() *CommitmentCircuit {
	return &CommitmentCircuit{}
}

func (circuit *CommitmentCircuit) Define(api frontend.API) error {
	commitment, err := circuit.Compute(api)
	if err != nil {
		return fmt.Errorf("failed to compute commitment: %w", err)
	}
	api.AssertIsEqual(circuit.Commitment, commitment)

	return nil
}

func TestCommitment_Circuit_Verification(t *testing.T) {
	// Test commitment circuit verification
	commitment := &builder.Commitment{
		Asset:        fr.NewElement(12345),
		Amount:       fr.NewElement(67890),
		OwnerPubKey:  twistededwardbn254.PointAffine{X: fr.NewElement(1), Y: fr.NewElement(2)},
		SpentAddress: fr.NewElement(3),
		ViewPubKey:   twistededwardbn254.PointAffine{X: fr.NewElement(4), Y: fr.NewElement(5)},
		AuditPubKey:  twistededwardbn254.PointAffine{X: fr.NewElement(6), Y: fr.NewElement(7)},
		FreezeFlag:   fr.NewElement(9),
		Blinding:     fr.NewElement(10),
	}

	circuit := NewCommitmentCircuit()
	require.NotNil(t, circuit)

	assert := test.NewAssert(t)

	// Create witness
	witness := CommitmentCircuit{
		CommitmentGadget: *commitment.ToGadget(),
		Commitment:       commitment.Compute(),
	}

	// Verify circuit
	options := test.WithCurves(ecc.BN254)
	assert.ProverSucceeded(circuit, &witness, options)
}

func TestCommitment_Circuit_InvalidWitness(t *testing.T) {
	// Test circuit verification with invalid witness
	commitment := &builder.Commitment{
		Asset:        fr.NewElement(12345),
		Amount:       fr.NewElement(67890),
		OwnerPubKey:  twistededwardbn254.PointAffine{X: fr.NewElement(1), Y: fr.NewElement(2)},
		SpentAddress: fr.NewElement(3),
		ViewPubKey:   twistededwardbn254.PointAffine{X: fr.NewElement(4), Y: fr.NewElement(5)},
		AuditPubKey:  twistededwardbn254.PointAffine{X: fr.NewElement(6), Y: fr.NewElement(7)},
		FreezeFlag:   fr.NewElement(9),
		Blinding:     fr.NewElement(10),
	}

	circuit := NewCommitmentCircuit()
	require.NotNil(t, circuit)

	assert := test.NewAssert(t)

	// Create invalid witness (wrong commitment value)
	witness := CommitmentCircuit{
		CommitmentGadget: *commitment.ToGadget(),
		Commitment:       commitment.Compute(),
	}
	witness.Commitment = fr.NewElement(99999) // Wrong commitment value

	// Circuit verification should fail
	options := test.WithCurves(ecc.BN254)
	assert.ProverFailed(circuit, &witness, options)
}

func TestCommitment_Circuit_DifferentInputs(t *testing.T) {
	// Test circuit verification with different inputs
	testCases := []struct {
		name       string
		asset      uint64
		amount     uint64
		blinding   uint64
		shouldPass bool
	}{
		{
			name:       "Valid commitment",
			asset:      12345,
			amount:     67890,
			blinding:   11111,
			shouldPass: true,
		},
		{
			name:       "Zero values",
			asset:      0,
			amount:     0,
			blinding:   0,
			shouldPass: true,
		},
		{
			name:       "Large values",
			asset:      0xFFFFFFFFFFFFFFFF,
			amount:     0xFFFFFFFFFFFFFFFF,
			blinding:   0xFFFFFFFFFFFFFFFF,
			shouldPass: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			commitment := &builder.Commitment{
				Asset:    fr.NewElement(tc.asset),
				Amount:   fr.NewElement(tc.amount),
				Blinding: fr.NewElement(tc.blinding),
			}

			circuit := NewCommitmentCircuit()
			require.NotNil(t, circuit)

			witness := CommitmentCircuit{
				CommitmentGadget: *commitment.ToGadget(),
				Commitment:       commitment.Compute(),
			}
			require.NotNil(t, witness)

			assert := test.NewAssert(t)

			options := test.WithCurves(ecc.BN254)

			if tc.shouldPass {
				assert.ProverSucceeded(circuit, &witness, options)
			} else {
				assert.ProverFailed(circuit, &witness, options)
			}
		})
	}
}
