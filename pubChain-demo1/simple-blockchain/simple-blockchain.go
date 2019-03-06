package main

// https://blog.csdn.net/yang731227/article/details/82932990

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strconv"
	"time"
)

// Block represent the block
type Block struct {
	Index         int64
	Timestamp     int64
	Data          []byte
	PrevBlockHash []byte
	Hash          []byte
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
func NewBlock(index int64, data, prevBlockHash []byte) *Block {
	block := &Block{index, time.Now().Unix(), data, prevBlockHash, []byte{}}
	block.SetHash()
	return block
}

// Blockchain is the distribute ledger
type Blockchain struct {
	blocks []*Block
}

// AddBlock add a new block to blockchain
func (bc *Blockchain) AddBlock(data string) {
	prevBlock := bc.blocks[len(bc.blocks)-1]
	newBlock := NewBlock(prevBlock.Index+1, []byte(data), prevBlock.Hash)
	bc.blocks = append(bc.blocks, newBlock)
}

// NewGenesisBlock create genesis block
func NewGenesisBlock() *Block {
	return NewBlock(0, []byte("Genesis Block"), []byte{})
}

// NewBlockchain create a new blockchain
func NewBlockchain() *Blockchain {
	return &Blockchain{[]*Block{NewGenesisBlock()}}
}

func main() {
	bc := NewBlockchain()
	bc.AddBlock("Send 1 BTC to Ivan")
	bc.AddBlock("Send 2 more BTC to Ivan")

	for _, block := range bc.blocks {
		fmt.Printf("Index :%d\n", block.Index)
		fmt.Printf("TimeStamp: %d\n", block.Timestamp)
		fmt.Printf("Data: %s\n", block.Data)
		fmt.Printf("PrevHash: %x\n", block.PrevBlockHash)
		fmt.Printf("Hash: %x\n", block.Hash)
		fmt.Println("_____________________________")
	}
}
