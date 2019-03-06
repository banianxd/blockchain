package main

// https://blog.csdn.net/yang731227/article/details/82987864

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"time"

	"github.com/boltdb/bolt"
)

const (
	targetBits = 5               // difficulty
	dbName     = "blockchain.db" // database name
	bkName     = "blocks"        // bucket name
)

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

// Serialize 使用BlotDB的前提就是，它的K-V都只能存储byte数组
// serialize Block to []byte
func (b *Block) Serialize() []byte {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)
	err := encoder.Encode(b)
	if err != nil {
		log.Panicf("serialize the block to byte failed %v \n", err)
	}
	return result.Bytes()
}

// DeserilizeBlock convert []byte to Block
func DeserilizeBlock(blockBytes []byte) *Block {
	var block Block
	decoder := gob.NewDecoder(bytes.NewReader(blockBytes))
	err := decoder.Decode(&block)
	if err != nil {
		log.Panicf("deserialize the block to byte failed %v \n", err)
	}
	return &block
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
	// blocks []*Block
	tip []byte   // 最新区块的hash
	Db  *bolt.DB // database
}

// AddBlock add a new block to blockchain
func (bc *Blockchain) AddBlock(data string) {
	/*prevBlock := bc.blocks[len(bc.blocks)-1]
	newBlock := NewBlock(prevBlock.Index+1, data, prevBlock.Hash)
	bc.blocks = append(bc.blocks, newBlock)*/

	err := bc.Db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bkName))
		if b != nil {
			blockBytes := b.Get(bc.tip)
			latestBlock := DeserilizeBlock(blockBytes)
			newBlock := NewBlock(latestBlock.Index+1, data, latestBlock.Hash)

			err := b.Put(newBlock.Hash, newBlock.Serialize())
			if nil != err {
				log.Panicf("put the data of new block into Dbfailed! %v\n", err)
			}
			err = b.Put([]byte("l"), newBlock.Hash)
			if nil != err {
				log.Panicf("put the hash of the newest block into Dbfailed! %v\n", err)
			}
			bc.tip = newBlock.Hash
		}

		return nil
	})

	if nil != err {
		log.Panicf("update the Dbof block failed! %v\n", err)
	}
}

// PrintChain print all blockchain data
func (bc *Blockchain) PrintChain() {
	fmt.Println("——————————————打印区块链———————————————————————")
	var curBlock *Block
	var curHash = bc.tip
	for {
		fmt.Println("—————————————————————————————————————————————")
		bc.Db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(bkName))
			if b != nil {
				blockBytes := b.Get(curHash)
				curBlock = DeserilizeBlock(blockBytes)

				fmt.Printf("\tHeigth : %d\n", curBlock.Index)
				fmt.Printf("\tTimeStamp : %d\n", curBlock.Timestamp)
				fmt.Printf("\tPrevBlockHash : %x\n", curBlock.PrevBlockHash)
				fmt.Printf("\tHash : %x\n", curBlock.Hash)
				fmt.Printf("\tData : %s\n", string(curBlock.Data))
				fmt.Printf("\tNonce : %d\n", curBlock.Nonce)
			}
			return nil
		})

		// 判断是否已经遍历到 genesis block
		var hashInt big.Int
		hashInt.SetBytes(curBlock.PrevBlockHash)
		if big.NewInt(0).Cmp(&hashInt) == 0 {
			break
		}
		curHash = curBlock.PrevBlockHash
	}
}

// NewGenesisBlock create genesis block
func NewGenesisBlock() *Block {
	return NewBlock(0, "Genesis Block", []byte{})
}

// BlockchainGenesisBlock create blockchain
func BlockchainGenesisBlock() *Blockchain {
	db, err := bolt.Open(dbName, 0600, nil)
	if err != nil {
		log.Panicf("open the Dbfailed! %v\n", err)
	}
	// defer db.Close()
	var tip []byte // 存储数据库中的区块哈希
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bkName))
		if b == nil {
			b, err = tx.CreateBucket([]byte(bkName))
			if err != nil {
				log.Panicf("create the bucket [%s] failed! %v\n", bkName, err)
			}
		}

		if b != nil {
			genesisBlock := NewGenesisBlock()
			// 存储创世区块
			err = b.Put(genesisBlock.Hash, genesisBlock.Serialize())
			if err != nil {
				log.Panicf("put the data of genesisBlock to Dbfailed! %v\n", err)
			}
			// 存储最新的区块链hash
			err = b.Put([]byte("l"), genesisBlock.Hash)
			if err != nil {
				log.Panicf("put the hash of latest block to Dbfailed! %v\n", err)
			}
			tip = genesisBlock.Hash
		}
		return nil
	})

	if err != nil {
		log.Panicf("update the data of genesis block failed! %v\n", err)
	}
	return &Blockchain{tip, db}
}

// NewBlockchain create a new blockchain
/*func NewBlockchain() *Blockchain {
	return &Blockchain{[]*Block{NewGenesisBlock()}}
}*/

func main() {
	blockchain := BlockchainGenesisBlock()
	defer blockchain.Db.Close()
	blockchain.AddBlock("Send 100 btc to Jay")
	blockchain.AddBlock("Send 50 btc to Clown")
	blockchain.AddBlock("Send 20 btc to Bob")
	blockchain.PrintChain()

	/*bc := NewBlockchain()
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
	}*/
}
