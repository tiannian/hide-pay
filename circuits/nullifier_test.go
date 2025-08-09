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
	"github.com/stretchr/testify/assert"
)

type NullifierCircuit struct {
	circuits.NullifierGadget
	Nullifier frontend.Variable `gnark:"nullifier,public"`
}

func NewNullifierCircuit() *NullifierCircuit {
	return &NullifierCircuit{}
}

func (circuit *NullifierCircuit) Define(api frontend.API) error {
	nullifier, err := circuit.NullifierGadget.Compute(api)
	if err != nil {
		return fmt.Errorf("failed to compute nullifier: %w", err)
	}
	api.AssertIsEqual(circuit.Nullifier, nullifier)

	return nil
}

func TestNullifier_Circuit_Verification(t *testing.T) {
	// Test nullifier circuit verification
	nullifier := &builder.Nullifier{
		Commitment: builder.Commitment{
			Asset:        fr.NewElement(12345),
			Amount:       fr.NewElement(67890),
			OwnerPubKey:  twistededwardbn254.PointAffine{X: fr.NewElement(1), Y: fr.NewElement(2)},
			SpentAddress: fr.NewElement(3),
			ViewPubKey:   twistededwardbn254.PointAffine{X: fr.NewElement(4), Y: fr.NewElement(5)},
			AuditPubKey:  twistededwardbn254.PointAffine{X: fr.NewElement(6), Y: fr.NewElement(7)},
			FreezeFlag:   fr.NewElement(9),
			Blinding:     fr.NewElement(11111),
		},
		SpentPrivateKey: fr.NewElement(22222),
	}

	circuit := NewNullifierCircuit()
	assert.NotNil(t, circuit)

	assert := test.NewAssert(t)

	// Create witness
	witness := NullifierCircuit{
		NullifierGadget: *nullifier.ToGadget(),
		Nullifier:       nullifier.Compute(),
	}

	// Verify circuit

	options := test.WithCurves(ecc.BN254)
	assert.ProverSucceeded(circuit, &witness, options)
}

func TestNullifier_Circuit_InvalidWitness(t *testing.T) {
	// Test circuit verification with invalid witness
	nullifier := &builder.Nullifier{
		Commitment: builder.Commitment{
			Asset:        fr.NewElement(12345),
			Amount:       fr.NewElement(67890),
			OwnerPubKey:  twistededwardbn254.PointAffine{X: fr.NewElement(1), Y: fr.NewElement(2)},
			SpentAddress: fr.NewElement(3),
			ViewPubKey:   twistededwardbn254.PointAffine{X: fr.NewElement(4), Y: fr.NewElement(5)},
			AuditPubKey:  twistededwardbn254.PointAffine{X: fr.NewElement(6), Y: fr.NewElement(7)},
			FreezeFlag:   fr.NewElement(9),
			Blinding:     fr.NewElement(11111),
		},
		SpentPrivateKey: fr.NewElement(22222),
	}

	circuit := NewNullifierCircuit()
	assert.NotNil(t, circuit)

	assert := test.NewAssert(t)

	// Create invalid witness (wrong nullifier value)
	witness := NullifierCircuit{
		NullifierGadget: *nullifier.ToGadget(),
		Nullifier:       nullifier.Compute(),
	}
	witness.Nullifier = fr.NewElement(99999) // Wrong nullifier value

	// Verify circuit should fail
	options := test.WithCurves(ecc.BN254)
	assert.ProverFailed(circuit, &witness, options)
}

func TestNullifier_Circuit_DifferentInputs(t *testing.T) {
	// Test circuit verification with different input combinations
	testCases := []struct {
		name         string
		asset        uint64
		amount       uint64
		ownerPubKey  [2]uint64
		spentAddress uint64
		viewPubKey   [2]uint64
		auditPubKey  [2]uint64
		freezeFlag   uint64
		blinding     uint64
		privateKey   uint64
	}{
		{"small_values", 1, 2, [2]uint64{3, 4}, 5, [2]uint64{6, 7}, [2]uint64{8, 9}, 10, 11, 12},
		{"medium_values", 1000, 2000, [2]uint64{3000, 4000}, 5000, [2]uint64{6000, 7000}, [2]uint64{8000, 9000}, 10000, 11000, 12000},
		{"large_values", 1000000, 2000000, [2]uint64{3000000, 4000000}, 5000000, [2]uint64{6000000, 7000000}, [2]uint64{8000000, 9000000}, 10000000, 11000000, 12000000},
		{"mixed_values", 123, 456789, [2]uint64{987, 654321}, 987654, [2]uint64{321, 987654}, [2]uint64{321, 987654}, 987654, 321, 987654},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nullifier := &builder.Nullifier{
				Commitment: builder.Commitment{
					Asset:    fr.NewElement(tc.asset),
					Amount:   fr.NewElement(tc.amount),
					Blinding: fr.NewElement(tc.blinding),
				},
				SpentPrivateKey: fr.NewElement(tc.privateKey),
			}

			circuit := NewNullifierCircuit()
			assert.NotNil(t, circuit)

			assert := test.NewAssert(t)

			witness := NullifierCircuit{
				NullifierGadget: *nullifier.ToGadget(),
				Nullifier:       nullifier.Compute(),
			}

			options := test.WithCurves(ecc.BN254)
			assert.ProverSucceeded(circuit, &witness, options)
		})
	}
}

func TestNullifier_Compute_EdgeCases(t *testing.T) {
	// Test edge cases
	testCases := []struct {
		name         string
		asset        uint64
		amount       uint64
		ownerPubKey  [2]uint64
		spentAddress uint64
		viewPubKey   [2]uint64
		auditPubKey  [2]uint64
		freezeFlag   uint64
		blinding     uint64
		privateKey   uint64
	}{
		{"all_zeros", 0, 0, [2]uint64{0, 0}, 0, [2]uint64{0, 0}, [2]uint64{0, 0}, 0, 0, 0},
		{"all_ones", 1, 1, [2]uint64{1, 1}, 1, [2]uint64{1, 1}, [2]uint64{1, 1}, 1, 1, 1},
		{"max_values", 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, [2]uint64{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, 0xFFFFFFFFFFFFFFFF, [2]uint64{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, [2]uint64{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
		{"mixed_zeros", 0, 12345, [2]uint64{0, 0}, 0, [2]uint64{0, 0}, [2]uint64{0, 0}, 0, 0, 0},
		{"mixed_max", 0xFFFFFFFFFFFFFFFF, 12345, [2]uint64{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, 67890, [2]uint64{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, [2]uint64{0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nullifier := &builder.Nullifier{
				Commitment: builder.Commitment{
					Asset:    fr.NewElement(tc.asset),
					Amount:   fr.NewElement(tc.amount),
					Blinding: fr.NewElement(tc.blinding),
				},
				SpentPrivateKey: fr.NewElement(tc.privateKey),
			}

			result := nullifier.Compute()
			assert.NotEqual(t, fr.Element{}, result)

			// Test circuit verification for edge cases
			circuit := NewNullifierCircuit()
			assert.NotNil(t, circuit)

			assert := test.NewAssert(t)

			witness := NullifierCircuit{
				NullifierGadget: *nullifier.ToGadget(),
				Nullifier:       result,
			}

			options := test.WithCurves(ecc.BN254)
			assert.ProverSucceeded(circuit, &witness, options)
		})
	}
}
