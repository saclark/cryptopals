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
func CrackECB(maxBlockSize int, encrypt OracleEncryptFunc) ([]byte, error) {
	k, err := DetectBlockSize(maxBlockSize, encrypt)
	if err != nil {
		return nil, fmt.Errorf("detecting block size: %w", err)
	}

	mode, err := DetectMode(k, encrypt)
	if err != nil {
		return nil, fmt.Errorf("detecting mode: %w", err)
	}

	if mode != ModeECB {
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

	plaintext := []byte{}
	var i int
	for {
		// Avoid decrypting previously decrypted blocks.
		if i%k == 0 {
			if j, ok := refs[i]; ok {
				plaintext = append(plaintext, plaintext[j:j+k]...)
				i += k
				continue
			}
		}

		if i < k {
			copy(inputBuf[k-1-i:], plaintext)
		} else {
			copy(inputBuf, plaintext[(i-k)+1:])
		}

		// Note: A possible optimization would be to test bytes in order of some
		// statistical likelihood.
		var decrypted bool
		for j := 0; j < 256; j++ {
			b := byte(j)
			inputBuf[k-1] = b

			output, err := encrypt(inputBuf)
			if err != nil {
				return nil, fmt.Errorf("querying encryption oracle with \"%x\": %w", inputBuf, err)
			}

			if decrypted = bytes.Equal(targetBlocks[i], output[:k]); decrypted {
				plaintext = append(plaintext, b)
				break
			}
		}

		if decrypted {
			i++
			continue
		}

		if k >= len(ciphertext)-len(plaintext) && plaintext[len(plaintext)-1] == 0x01 {
			return plaintext[:len(plaintext)-1], nil
		}

		return plaintext, AttackFailedError("unable to decrypt byte at index " + strconv.Itoa(i))
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
