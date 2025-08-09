package builder

import (
	"fmt"
	"hash"
	"hide-pay/circuits"
	"hide-pay/utils"
	"math"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

type MerkleTree struct {
	tree            map[int]fr.Element
	depth           int
	hasher          hash.Hash
	latestLeafIndex int
}

func NewMerkleTree(depth int, hasher hash.Hash) *MerkleTree {
	return &MerkleTree{
		depth:  depth,
		hasher: hasher,
		tree:   make(map[int]fr.Element),
	}
}

func (mt *MerkleTree) Build(elems []fr.Element) {
	for i := range elems {
		mt.tree[i] = elems[i]
		mt.latestLeafIndex = i
	}

	sizeLayer := (len(elems)/2 + 1)
	latestLayerBegin := 0

	for i := 1; i < mt.depth; i++ {
		thisLayerBegin := latestLayerBegin + int(math.Pow(2, float64(mt.depth-i)))

		if sizeLayer == 0 {
			sizeLayer = 1
		}

		for j := 0; j < sizeLayer; j++ {
			leftIndex := latestLayerBegin + j*2
			rightIndex := leftIndex + 1

			leftNode := mt.tree[leftIndex]
			rightNode := mt.tree[rightIndex]

			sumElem := hashElement(mt.hasher, leftNode, rightNode)

			mt.tree[thisLayerBegin+j] = sumElem
		}

		sizeLayer = sizeLayer / 2
		latestLayerBegin = thisLayerBegin
	}
}

func (mt *MerkleTree) AppendSingle(elem fr.Element) {
	flag := utils.IntToBits(mt.latestLeafIndex, mt.depth)

	root := elem

	thisLayerBegin := 0
	groupThisLayer := mt.latestLeafIndex

	for i := 0; i < len(flag); i++ {
		mt.tree[thisLayerBegin+groupThisLayer] = root
		if flag[i] {
			// fmt.Println("flag[i] is true, group index is", groupThisLayer, thisLayerBegin+groupThisLayer-1)
			root = hashElement(mt.hasher, mt.tree[thisLayerBegin+groupThisLayer-1], root)
		} else {
			// fmt.Println("flag[i] is false, group index is", groupThisLayer, thisLayerBegin+groupThisLayer+1)
			root = hashElement(mt.hasher, root, mt.tree[thisLayerBegin+groupThisLayer+1])
		}

		thisLayerBegin = thisLayerBegin + int(math.Pow(2, float64(mt.depth-1-i)))
		groupThisLayer = groupThisLayer / 2
	}

	mt.latestLeafIndex = mt.latestLeafIndex + 1
}

func (mt *MerkleTree) GetRoot() fr.Element {
	rootIndex := 0

	for i := 0; i < mt.depth-1; i++ {
		rootIndex = rootIndex + int(math.Pow(2, float64(mt.depth-1-i)))
	}

	return mt.tree[rootIndex]
}

func (mt *MerkleTree) PrintTree() {
	for i, v := range mt.tree {
		fmt.Println(i, v.Text(10))
	}
}

func (mt *MerkleTree) GetProof(index int) MerkleProof {
	proof := make([]fr.Element, mt.depth)

	proof[0] = mt.tree[index]

	flag := utils.IntToBits(index, mt.depth)

	thisLayerBegin := 0
	groupThisLayer := index

	for i := 0; i < len(flag)-1; i++ {
		if flag[i] {
			// fmt.Println("flag[i] is true, group index is", groupThisLayer, thisLayerBegin+groupThisLayer-1)
			proof[i+1] = mt.tree[thisLayerBegin+groupThisLayer-1]
		} else {
			// fmt.Println("flag[i] is false, group index is", groupThisLayer, thisLayerBegin+groupThisLayer+1)
			proof[i+1] = mt.tree[thisLayerBegin+groupThisLayer+1]
		}

		thisLayerBegin = thisLayerBegin + int(math.Pow(2, float64(mt.depth-1-i)))
		groupThisLayer = groupThisLayer / 2
	}

	return MerkleProof{
		proof:  proof,
		depth:  mt.depth,
		hasher: mt.hasher,
		index:  index,
	}
}

type MerkleProof struct {
	proof  []fr.Element
	index  int
	depth  int
	hasher hash.Hash
}

func (mp *MerkleProof) PrintProof() {
	for _, v := range mp.proof {
		fmt.Println(v.Text(10))
	}
}

func (mp *MerkleProof) Verify() fr.Element {
	flag := utils.IntToBits(mp.index, mp.depth)

	root := mp.proof[0]

	for i := 0; i < len(flag)-1; i++ {
		if flag[i] {
			// fmt.Println("hash ", mp.proof[i+1].Text(10), "and", root.Text(10))
			root = hashElement(mp.hasher, mp.proof[i+1], root)
		} else {
			// fmt.Println("hash ", root.Text(10), "and", mp.proof[i+1].Text(10))
			root = hashElement(mp.hasher, root, mp.proof[i+1])
		}
	}

	return root
}

func (mp *MerkleProof) ToGadget() *circuits.MerkleProofGadget {
	path := make([]frontend.Variable, len(mp.proof))

	for i := range mp.proof {
		path[i] = mp.proof[i]
	}

	return &circuits.MerkleProofGadget{
		Path: path,
		Leaf: mp.index,
	}
}

func hashElement(hasher hash.Hash, a, b fr.Element) fr.Element {
	aBytes := a.Bytes()
	bBytes := b.Bytes()

	hasher.Reset()
	hasher.Write(aBytes[:])
	hasher.Write(bBytes[:])

	sum := hasher.Sum(nil)
	sumElem := fr.Element{}
	sumElem.SetBytes(sum)

	return sumElem
}
