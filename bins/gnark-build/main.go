package main

import (
	"bytes"
	"fmt"
	"hide-pay/builder"
	"hide-pay/circuits"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	receiverPublicKey, _, err := circuits.CreatePublicFromRand()
	if err != nil {
		panic(err)
	}

	auditPublicKey, _, err := circuits.CreatePublicFromRand()
	if err != nil {
		panic(err)
	}

	_, senderSecretKey, err := circuits.CreatePublicFromRand()
	if err != nil {
		panic(err)
	}

	blinding0, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	blinding1, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	blinding2, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	blinding3, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	blinding4, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	blinding5, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	blinding6, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	blinding7, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralReceiverSecretKey1, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralReceiverSecretKey2, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralReceiverSecretKey3, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralReceiverSecretKey4, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralAuditSecretKey1, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralAuditSecretKey2, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralAuditSecretKey3, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	EphemeralAuditSecretKey4, err := circuits.CreateSeedFromRand()
	if err != nil {
		panic(err)
	}

	nullifier := circuits.Nullifier{
		Commitment: circuits.Commitment{
			Asset:    fr.NewElement(1),
			Amount:   fr.NewElement(2),
			Blinding: circuits.BigIntToFr(blinding0),
		},
		PrivateKey: circuits.BigIntToFr(senderSecretKey),
	}

	nullifier0 := nullifier
	nullifier1 := nullifier
	nullifier2 := nullifier
	nullifier3 := nullifier

	nullifier0.Blinding = circuits.BigIntToFr(blinding0)
	nullifier1.Blinding = circuits.BigIntToFr(blinding1)
	nullifier2.Blinding = circuits.BigIntToFr(blinding2)
	nullifier3.Blinding = circuits.BigIntToFr(blinding3)

	depth := 34

	merkleTree := builder.NewMerkleTree(depth, poseidon2.NewMerkleDamgardHasher())
	elems := []fr.Element{
		nullifier0.Commitment.Compute(),
		nullifier1.Commitment.Compute(),
		nullifier2.Commitment.Compute(),
		nullifier3.Commitment.Compute(),
	}
	merkleTree.Build(elems)

	merkleProof0 := merkleTree.GetProof(0)
	merkleProof1 := merkleTree.GetProof(1)
	merkleProof2 := merkleTree.GetProof(2)
	merkleProof3 := merkleTree.GetProof(3)

	utxo := &builder.UTXO{
		Nullifier: []circuits.Nullifier{
			nullifier0,
			nullifier1,
			nullifier2,
			nullifier3,
		},
		MerkleProof: []builder.MerkleProof{
			merkleProof0,
			merkleProof1,
			merkleProof2,
			merkleProof3,
		},
		Commitment: []circuits.Commitment{
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: circuits.BigIntToFr(blinding4),
			},
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: circuits.BigIntToFr(blinding5),
			},
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: circuits.BigIntToFr(blinding6),
			},
			{
				Asset:    fr.NewElement(1),
				Amount:   fr.NewElement(2),
				Blinding: circuits.BigIntToFr(blinding7),
			},
		},
		EphemeralViewSecretKey: []big.Int{
			EphemeralReceiverSecretKey1,
			EphemeralReceiverSecretKey2,
			EphemeralReceiverSecretKey3,
			EphemeralReceiverSecretKey4,
		},
		EphemeralAuditSecretKey: []big.Int{
			EphemeralAuditSecretKey1,
			EphemeralAuditSecretKey2,
			EphemeralAuditSecretKey3,
			EphemeralAuditSecretKey4,
		},
		ViewPublicKey:  receiverPublicKey.PointAffine,
		AuditPublicKey: auditPublicKey.PointAffine,
	}

	result, err := utxo.BuildAndCheck()
	if err != nil {
		panic(err)
	}

	assignment, err := builder.NewUTXOCircuitWitness(utxo, result)
	if err != nil {
		panic("build assignment: " + err.Error())
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic("build witness: " + err.Error())
	}

	publicWitness, err := witness.Public()
	if err != nil {
		panic("build public witness: " + err.Error())
	}

	utxoCircuit := circuits.NewUTXOCircuit(len(result.AllAsset), depth, len(utxo.Nullifier), len(utxo.Commitment))

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, utxoCircuit)
	if err != nil {
		panic("compile: " + err.Error())
	}

	var csBuf bytes.Buffer
	_, err = cs.WriteTo(&csBuf)
	if err != nil {
		panic("write cs: " + err.Error())
	}
	os.WriteFile("./target/cs.dat", csBuf.Bytes(), 0644)

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic("setup: " + err.Error())
	}

	var pkBuf bytes.Buffer
	_, err = pk.WriteRawTo(&pkBuf)
	if err != nil {
		panic("write pk: " + err.Error())
	}

	os.WriteFile("./target/pk.dat", pkBuf.Bytes(), 0644)

	var vkBuf bytes.Buffer
	_, err = vk.WriteRawTo(&vkBuf)
	if err != nil {
		panic("write vk: " + err.Error())
	}

	os.WriteFile("./target/vk.dat", vkBuf.Bytes(), 0644)

	start := time.Now()

	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic("prove: " + err.Error())
	}

	elapsed := time.Since(start)
	fmt.Println("Prove time:", elapsed)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}
