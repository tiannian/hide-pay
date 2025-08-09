package circuits_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"

	"hide-pay/builder"
	"hide-pay/circuits"
	"hide-pay/utils"
)

type MemoCircuit struct {
	SecretKey  frontend.Variable
	PublicKey  [2]frontend.Variable
	Commitment circuits.CommitmentGadget

	OwnerMemoHash frontend.Variable
	AuditMemoHash frontend.Variable
}

func (circuit *MemoCircuit) Define(api frontend.API) error {
	gadget := circuits.MemoGadget{
		EphemeralSecretKey: circuit.SecretKey,
		ReceiverPublicKey:  circuit.PublicKey,
	}

	ownerMemo, err := gadget.Generate(api, circuit.Commitment)
	if err != nil {
		return fmt.Errorf("failed to generate commitment: %w", err)
	}

	api.AssertIsEqual(circuit.OwnerMemoHash, ownerMemo)

	auditMemo, err := gadget.Generate(api, circuit.Commitment)
	if err != nil {
		return fmt.Errorf("failed to generate commitment: %w", err)
	}

	api.AssertIsEqual(circuit.AuditMemoHash, auditMemo)

	return nil
}

func TestMemo_ToCircuit(t *testing.T) {
	secretKey := big.NewInt(11111)
	receiverSecretKey := big.NewInt(22222)
	receiverPublicKey := utils.BuildPublicKey(*receiverSecretKey)

	memo := &builder.Memo{
		SecretKey: *secretKey,
		PublicKey: receiverPublicKey,
	}

	commitment := &builder.Commitment{
		Asset:    fr.NewElement(12345),
		Amount:   fr.NewElement(67890),
		Blinding: fr.NewElement(11111),
	}

	_, ownerMemo, err := memo.Encrypt(*commitment)
	require.NoError(t, err)

	_, auditMemo, err := memo.Encrypt(*commitment)
	require.NoError(t, err)

	circuit := MemoCircuit{}

	witness := MemoCircuit{
		SecretKey: *secretKey,
		PublicKey: [2]frontend.Variable{receiverPublicKey.X, receiverPublicKey.Y},
		Commitment: circuits.CommitmentGadget{
			Asset:        commitment.Asset,
			Amount:       commitment.Amount,
			OwnerPubKey:  [2]frontend.Variable{commitment.OwnerPubKey.X, commitment.OwnerPubKey.Y},
			SpentAddress: commitment.SpentAddress,
			ViewPubKey:   [2]frontend.Variable{commitment.ViewPubKey.X, commitment.ViewPubKey.Y},
			AuditPubKey:  [2]frontend.Variable{commitment.AuditPubKey.X, commitment.AuditPubKey.Y},
			FreezeFlag:   commitment.FreezeFlag,
			Blinding:     commitment.Blinding,
		},
		OwnerMemoHash: ownerMemo[len(ownerMemo)-1],
		AuditMemoHash: auditMemo[len(auditMemo)-1],
	}

	assert := test.NewAssert(t)

	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))
}
