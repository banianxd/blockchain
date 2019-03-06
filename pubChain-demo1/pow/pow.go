package main

// https://blog.csdn.net/yang731227/article/details/82935098

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"time"
)

// difficulty
const targetBits = 5

// Block represent the block
type Block struct {
	Index         int64
	Timestamp     int64
	Data          []byte
	PrevBlockHash []byte
	Hash          []byte
	Nonce         int64
}

// SetHash set the block hash
func (b *Block) SetHash() {
	timestamp := []byte(strconv.FormatInt(b.Timestamp, 10))
	index := []byte(strconv.FormatInt(b.Index, 10))
	headers := bytes.Join([][]byte{timestamp, index, b.PrevBlockHash}, []byte{})
	hash := sha256.Sum256(headers)
	b.Hash = hash[:]
}

// NewBlock create a new block
func NewBlock(index int64, data string, prevBlockHash []byte) *Block {
	block := &Block{index, time.Now().Unix(), []byte(data), prevBlockHash, []byte{}, 0}
	pow := NewProofOfWork(block)
	nonce, hash := pow.Run()
	block.Hash = hash[:]
	block.Nonce = nonce
	return block
}

// ProofOfWork pow struct
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

// NewProofOfWork create a new block with difficulty
func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))
	pow := &ProofOfWork{b, target}
	return pow
}

// IntToHex convert int64 to []byte hex
func IntToHex(data int64) []byte {
	buffer := new(bytes.Buffer)
	err := binary.Write(buffer, binary.BigEndian, data)
	if nil != err {
		log.Panicf("int to []byte failed! %v\n", err)
	}
	return buffer.Bytes()
}

// prepareData get hash preimage
func (pow *ProofOfWork) prepareData(nonce int64) []byte {
	data := bytes.Join(
		[][]byte{
			pow.block.PrevBlockHash,
			pow.block.Data,
			IntToHex(pow.block.Index),
			IntToHex(pow.block.Timestamp),
			IntToHex(int64(targetBits)),
			IntToHex(nonce),
		},
		[]byte{},
	)
	return data
}

// Run run pow, return nonce and hash
func (pow *ProofOfWork) Run() (int64, []byte) {
	var hashInt big.Int
	var hash [32]byte
	var nonce int64
	fmt.Printf("Mining the block containing \"%s\"\n", pow.block.Data)
	for {
		dataBytes := pow.prepareData(nonce) // 获取hash preimage
		hash = sha256.Sum256(dataBytes)
		hashInt.SetBytes(hash[:])
		fmt.Printf("hash: \r%x\n", hash)
		if pow.target.Cmp(&hashInt) == 1 { // 计算的hash小于target
			break
		}
		nonce++ //充当计数器，同时在循环结束后也是符合要求的值
	}

	fmt.Printf("\n碰撞次数: %d\n", nonce)
	return nonce, hash[:]
}

// Validate validate block is valid
func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int
	data := pow.prepareData(pow.block.Nonce)
	hash := sha256.Sum256(data)
	hashInt.SetBytes(hash[:])
	isValid := hashInt.Cmp(pow.target) == -1
	return isValid
}

// Blockchain is the distribute ledger
type Blockchain struct {
	blocks []*Block
}

// AddBlock add a new block to blockchain
func (bc *Blockchain) AddBlock(data string) {
	prevBlock := bc.blocks[len(bc.blocks)-1]
	newBlock := NewBlock(prevBlock.Index+1, data, prevBlock.Hash)
	bc.blocks = append(bc.blocks, newBlock)
}

// NewGenesisBlock create genesis block
func NewGenesisBlock() *Block {
	return NewBlock(0, "Genesis Block", []byte{})
}

// NewBlockchain create a new blockchain
func NewBlockchain() *Blockchain {
	return &Blockchain{[]*Block{NewGenesisBlock()}}
}

func main() {
	bc := NewBlockchain()
	fmt.Printf("blockChain : %v\n", bc)
	bc.AddBlock("Aimi send 100 BTC	to Bob")
	bc.AddBlock("Aimi send 100 BTC	to Jay")
	bc.AddBlock("Aimi send 100 BTC	to Clown")
	length := len(bc.blocks)
	fmt.Printf("length of blocks : %d\n", length)

	for i := 0; i < length; i++ {
		pow := NewProofOfWork(bc.blocks[i])
		if pow.Validate() {
			fmt.Println("—————————————————————————————————————————————————————")
			fmt.Printf(" Block: %d\n", bc.blocks[i].Index)
			fmt.Printf("Data: %s\n", bc.blocks[i].Data)
			fmt.Printf("TimeStamp: %d\n", bc.blocks[i].Timestamp)
			fmt.Printf("Hash: %x\n", bc.blocks[i].Hash)
			fmt.Printf("PrevHash: %x\n", bc.blocks[i].PrevBlockHash)
			fmt.Printf("Nonce: %d\n", bc.blocks[i].Nonce)

		} else {
			fmt.Println("illegal block")
		}
	}
}
