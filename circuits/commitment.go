package circuits

import (
	"fmt"
	"hide-pay/utils"

	"github.com/consensys/gnark/frontend"
)

type CommitmentGadget struct {
	Asset        frontend.Variable    `gnark:"asset"`
	Amount       frontend.Variable    `gnark:"amount"`
	OwnerPubKey  [2]frontend.Variable `gnark:"ownerPubKey"`
	SpentAddress frontend.Variable    `gnark:"spentAddress"`
	ViewPubKey   [2]frontend.Variable `gnark:"viewPubKey"`
	AuditPubKey  [2]frontend.Variable `gnark:"auditPubKey"`
	FreezeFlag   frontend.Variable    `gnark:"freezeFlag"`
	Blinding     frontend.Variable    `gnark:"blinding"`
}

func (gadget *CommitmentGadget) Compute(api frontend.API) (frontend.Variable, error) {
	hasher, err := utils.NewPoseidonHasher(api)
	if err != nil {
		return nil, fmt.Errorf("failed to create poseidon hasher: %w", err)
	}

	hasher.Write(gadget.Asset)
	hasher.Write(gadget.Amount)
	hasher.Write(gadget.OwnerPubKey[0])
	hasher.Write(gadget.OwnerPubKey[1])
	hasher.Write(gadget.SpentAddress)
	hasher.Write(gadget.ViewPubKey[0])
	hasher.Write(gadget.ViewPubKey[1])
	hasher.Write(gadget.AuditPubKey[0])
	hasher.Write(gadget.AuditPubKey[1])
	hasher.Write(gadget.FreezeFlag)
	hasher.Write(gadget.Blinding)

	commitment := hasher.Sum()

	return commitment, nil
}
