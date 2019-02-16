package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"
	"time"
)

// https://mp.weixin.qq.com/s?__biz=MzAwMDU1MTE1OQ==&mid=2653549384&idx=1&sn=fce9e6fa059c044a6abfcf2cc3241ba5&chksm=813a62d0b64debc657e09718d6c851ee1cc7c37d3cb5b0a4213732a331dcd4bd5aae38a5fdf4&scene=21#wechat_redirect

// Block represents each 'item' in the blockchain
type Block struct {
	Index     int    // 这个块在整个链中的位置
	Timestamp string // 块生成时的时间戳
	BPM       int    // 每分钟心跳数，也就是心率
	Hash      string // 区块Hash
	PrevHash  string // 区块的前一个Hash
}

// Blockchain is a series of validated Blocks
var Blockchain []Block

var mutex = &sync.Mutex{}

// SHA256 hasing
func calculateHash(block Block) string {
	record := strconv.Itoa(block.Index) + block.Timestamp + strconv.Itoa(block.BPM) + block.PrevHash
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

// create a new block using previous block's hash
func generateBlock(oldBlock Block, BPM int) Block {
	var newBlock Block

	t := time.Now()
	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.BPM = BPM
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Hash = calculateHash(newBlock)

	return newBlock
}

// make sure block is valid by checking index, and comparing the hash of the previous block
func isBlockValid(newBlock, oldBlock Block) bool {
	if oldBlock.Index+1 != newBlock.Index {
		return false
	}
	if oldBlock.Hash != newBlock.PrevHash {
		return false
	}
	if calculateHash(newBlock) != newBlock.Hash {
		return false
	}
	return true
}

func main() {

}
