package attack

import (
	"bytes"
	"fmt"
	"strconv"
)

type AttackFailedError string

func (e AttackFailedError) Error() string {
	return string(e)
}

// CrackECB attempts to decrypt the unknown, internal data
// being handled by an AES encryption oracle that uses ECB mode with a static
// key and allows arbitrary input to be prepended the targeted internal data.
func CrackECB(maxBlockSize int, encrypt EncryptionOracle) ([]byte, error) {
	k, err := DetectBlockSize(maxBlockSize, encrypt)
	if err != nil {
		return nil, fmt.Errorf("detecting block size: %w", err)
	}

	ecbMode, err := IsECBMode(k, encrypt)
	if err != nil {
		return nil, fmt.Errorf("detecting ECB mode: %w", err)
	}
	if !ecbMode {
		return nil, AttackFailedError("not ECB mode")
	}

	ciphertext, err := encrypt([]byte{})
	if err != nil {
		return nil, fmt.Errorf("querying encryption oracle with empty input: %w", err)
	}

	refs, err := relateDuplicateBlocks(ciphertext, k)
	if err != nil {
		return nil, fmt.Errorf("relating duplicate ciphertext blocks: %w", err)
	}

	targetBlocks := make([][]byte, len(ciphertext))
	inputBuf := make([]byte, k)

	// Generate ciphertext blocks corresponding to one having taken the first
	// block-sized slice of the target plaintext, passed it into the encryption
	// oracle, and repeated, sliding it one byte to the right each time.
	for i := 0; i < k; i++ {
		output, err := encrypt(inputBuf[:k-1-i])
		if err != nil {
			return nil, fmt.Errorf("querying encryption oracle with \"%x\": %w", inputBuf[:k-1-i], err)
		}
		for j := 0; j+k <= len(output); j += k {
			if idx := i + (j/k)*k; idx < len(targetBlocks) {
				targetBlocks[idx] = output[j : j+k]
			}
		}
	}

	decrypted := []byte{}
	var i int
	for {
		// Avoid decrypting previously decrypted blocks.
		if i%k == 0 {
			if j, ok := refs[i]; ok {
				decrypted = append(decrypted, decrypted[j:j+k]...)
				i += k
				continue
			}
		}

		if i < k {
			copy(inputBuf[k-1-i:], decrypted)
		} else {
			copy(inputBuf, decrypted[(i-k)+1:])
		}

		// Note: A possible optimization would be to test bytes in order of some
		// statistical likelihood.
		var found bool
		for j := 0; j < 256; j++ {
			b := byte(j)
			inputBuf[k-1] = b

			output, err := encrypt(inputBuf)
			if err != nil {
				return nil, fmt.Errorf("querying encryption oracle with \"%x\": %w", inputBuf, err)
			}

			if found = bytes.Equal(targetBlocks[i], output[:k]); found {
				decrypted = append(decrypted, b)
				break
			}
		}

		if found {
			i++
			continue
		}

		if k >= len(ciphertext)-len(decrypted) && decrypted[len(decrypted)-1] == 0x01 {
			return decrypted[:len(decrypted)-1], nil
		}

		return decrypted, AttackFailedError("unable to decrypt byte at index " + strconv.Itoa(i))
	}
}

// relateDuplicateBlocks creates a map relating the index of the first byte of
// one ciphertext block to the index of the first byte of another matching
// ciphertext block that came before it, for all blocks that have a prior
// duplicate.
func relateDuplicateBlocks(ciphertext []byte, blockSize int) (map[int]int, error) {
	refs := map[int]int{}
	seen := make(map[string]int, len(ciphertext)/blockSize)
	for i := 0; i+blockSize <= len(ciphertext); i += blockSize {
		block := ciphertext[i : i+blockSize]
		if j, ok := seen[string(block)]; ok {
			refs[i] = j
		} else {
			seen[string(block)] = i
		}
	}
	return refs, nil
}

// IsECBMode detects whether an encryption oracle is using ECB mode.
func IsECBMode(blockSize int, encrypt EncryptionOracle) (bool, error) {
	ecbProbe := make([]byte, blockSize*blockSize)
	ciphertext, err := encrypt(ecbProbe)
	if err != nil {
		return false, fmt.Errorf("calling encrypt: %v", err)
	}
	score := DetectECBMode(ciphertext[:len(ecbProbe)], blockSize)
	return score >= 0.1, nil
}

// DetectECBMode returns a number in the range [0, 1] indicating the fraction of
// ciphertext blocks that are duplicated. A higher score indicates a higher
// likelihood that the ciphertext was encrypted with ECB. It panics if
// ciphertext is not a multiple of BlockSize.
func DetectECBMode(ciphertext []byte, blockSize int) float64 {
	if len(ciphertext) == 0 {
		return 0
	}

	if len(ciphertext)%blockSize != 0 {
		panic("aes.DetectECB: ciphertext size not a multiple of block size")
	}

	n := len(ciphertext) / blockSize
	uniques := make(map[string]struct{}, n)
	for i := 0; i+blockSize < len(ciphertext); i += blockSize {
		uniques[string(ciphertext[i:i+blockSize])] = struct{}{}
	}

	return float64(n-len(uniques)) / float64(n)
}
