package hashes

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/mfonda/simhash"
	"github.com/spaolacci/murmur3"
)

func stdBase64(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}

func Mmh3(data []byte) string {
	var h32 = murmur3.New32WithSeed(0)
	h32.Write(stdBase64(data))
	return fmt.Sprintf("%d", int32(h32.Sum32()))
}

func Md5(data []byte) string {
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

func Sha1(data []byte) string {
	hash := sha1.Sum(data)
	return hex.EncodeToString(hash[:])
}

func Sha256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func Sha224(data []byte) string {
	hash := sha256.Sum224(data)
	return hex.EncodeToString(hash[:])
}

func Sha512(data []byte) string {
	hash := sha512.Sum512(data)
	return hex.EncodeToString(hash[:])
}

func Simhash(data []byte) string {
	hash := simhash.Simhash(simhash.NewWordFeatureSet(data))
	return fmt.Sprintf("%d", hash)
}
