#!/bin/bash

CIRCOM_NAME=$1
PTAU_SIZE=$2

mkdir -p target/circuits
mkdir -p target/ptaus

circom circuits/circom/${CIRCOM_NAME}.circom --r1cs --wasm -o target/circuits/ -l libs/circomlib/circuits || exit 1

cd target/circuits || exit 1

if [ ! -f ../ptaus/powersOfTau28_hez_final_${PTAU_SIZE}.ptau ]; then
    echo "PTAU file not found, downloading..."
    curl -o ../ptaus/powersOfTau28_hez_final_${PTAU_SIZE}.ptau https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_${PTAU_SIZE}.ptau || exit 1
fi

snarkjs groth16 setup ${CIRCOM_NAME}.r1cs ../ptaus/powersOfTau28_hez_final_${PTAU_SIZE}.ptau ${CIRCOM_NAME}_0000.zkey || exit 1
snarkjs zkey contribute ${CIRCOM_NAME}_0000.zkey ${CIRCOM_NAME}_0001.zkey --name="First contribution" -v || exit 1
snarkjs zkey export verificationkey ${CIRCOM_NAME}_0001.zkey ${CIRCOM_NAME}_verification_key.json || exit 1
