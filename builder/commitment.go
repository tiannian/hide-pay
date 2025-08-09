package builder

import (
	"fmt"
	"hide-pay/circuits"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	twistededwardbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
)

type Commitment struct {
	Asset        fr.Element
	Amount       fr.Element
	OwnerPubKey  twistededwardbn254.PointAffine
	SpentAddress fr.Element
	ViewPubKey   twistededwardbn254.PointAffine
	AuditPubKey  twistededwardbn254.PointAffine
	FreezeFlag   fr.Element
	Blinding     fr.Element
}

func (commitment *Commitment) ToGadget() *circuits.CommitmentGadget {
	return &circuits.CommitmentGadget{
		Asset:        commitment.Asset,
		Amount:       commitment.Amount,
		OwnerPubKey:  [2]frontend.Variable{commitment.OwnerPubKey.X, commitment.OwnerPubKey.Y},
		SpentAddress: commitment.SpentAddress,
		ViewPubKey:   [2]frontend.Variable{commitment.ViewPubKey.X, commitment.ViewPubKey.Y},
		AuditPubKey:  [2]frontend.Variable{commitment.AuditPubKey.X, commitment.AuditPubKey.Y},
		FreezeFlag:   commitment.FreezeFlag,
		Blinding:     commitment.Blinding,
	}
}

func formatPoint(point twistededwardbn254.PointAffine) string {
	return fmt.Sprintf("(%s, %s)", point.X.Text(10), point.Y.Text(10))
}

func (commitment *Commitment) String() string {
	assetStr := fmt.Sprintf("Asset: %s", commitment.Asset.Text(10))
	amountStr := fmt.Sprintf("Amount: %s", commitment.Amount.Text(10))
	blindingStr := fmt.Sprintf("Blinding: %s", commitment.Blinding.Text(10))
	ownerPubKey := fmt.Sprintf("OwnerPubKey: %s", formatPoint(commitment.OwnerPubKey))
	spentAddress := fmt.Sprintf("SpentAddress: %s", commitment.SpentAddress.Text(10))
	viewPubKey := fmt.Sprintf("ViewPubKey: %s", formatPoint(commitment.ViewPubKey))
	auditPubKey := fmt.Sprintf("AuditPubKey: %s", formatPoint(commitment.AuditPubKey))
	freezeFlag := fmt.Sprintf("FreezeFlag: %s", commitment.FreezeFlag.Text(10))
	return fmt.Sprintf("Commitment(%s,%s,%s,%s,%s,%s,%s,%s)",
		assetStr,
		amountStr,
		blindingStr,
		ownerPubKey,
		spentAddress,
		viewPubKey,
		auditPubKey,
		freezeFlag)
}

func (commitment *Commitment) Compute() fr.Element {
	hasher := poseidon2.NewMerkleDamgardHasher()

	assetBytes := commitment.Asset.Bytes()
	amountBytes := commitment.Amount.Bytes()
	ownerPubKeyXBytes := commitment.OwnerPubKey.X.Bytes()
	ownerPubKeyYBytes := commitment.OwnerPubKey.Y.Bytes()
	spentAddressBytes := commitment.SpentAddress.Bytes()
	viewPubKeyXBytes := commitment.ViewPubKey.X.Bytes()
	viewPubKeyYBytes := commitment.ViewPubKey.Y.Bytes()
	auditPubKeyXBytes := commitment.AuditPubKey.X.Bytes()
	auditPubKeyYBytes := commitment.AuditPubKey.Y.Bytes()
	freezeFlagBytes := commitment.FreezeFlag.Bytes()
	blindingBytes := commitment.Blinding.Bytes()

	hasher.Write(assetBytes[:])
	hasher.Write(amountBytes[:])
	hasher.Write(ownerPubKeyXBytes[:])
	hasher.Write(ownerPubKeyYBytes[:])
	hasher.Write(spentAddressBytes[:])
	hasher.Write(viewPubKeyXBytes[:])
	hasher.Write(viewPubKeyYBytes[:])
	hasher.Write(auditPubKeyXBytes[:])
	hasher.Write(auditPubKeyYBytes[:])
	hasher.Write(freezeFlagBytes[:])

	resBytes := hasher.Sum(blindingBytes[:])

	res := fr.Element{}
	res.Unmarshal(resBytes)

	return res
}
