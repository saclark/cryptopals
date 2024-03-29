package attack

import (
	"bytes"
	"fmt"
	"strconv"
)

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

	var duped int
	n := len(ciphertext) / blockSize
	seen := make(map[string]bool, n)
	for i := 0; i+blockSize <= len(ciphertext); i += blockSize {
		if duplicated, ok := seen[string(ciphertext[i:i+blockSize])]; ok {
			if !duplicated {
				duped += 2
				seen[string(ciphertext[i:i+blockSize])] = true
			} else {
				duped++
			}
		} else {
			seen[string(ciphertext[i:i+blockSize])] = false
		}
	}

	return float64(duped) / float64(n)
}

// IsOracleECBMode detects whether an encryption oracle is using ECB mode.
func IsOracleECBMode(blockSize int, encrypt EncryptionOracle) (bool, error) {
	ecbProbe := make([]byte, blockSize*blockSize)
	ciphertext, err := encrypt(ecbProbe)
	if err != nil {
		return false, fmt.Errorf("calling encrypt: %v", err)
	}
	score := DetectECBMode(ciphertext[:len(ecbProbe)], blockSize)
	return score > 0, nil
}

// byteSearchOrder makes a very rough attempt at listing each of the
// possible 256 bytes in order from most likely to occur to least likely to
// occur in any given plaintext.
var byteSearchOrder = []int{
	32, 101, 116, 97, 111, 110, 105, 115, 114, 104, 100, 108, 117, 99, 109, 102,
	119, 103, 121, 112, 98, 118, 107, 120, 106, 113, 122, 69, 84, 65, 79, 78,
	73, 83, 82, 72, 68, 76, 85, 67, 77, 70, 87, 71, 89, 80, 66, 86, 75, 88, 74,
	81, 90, 46, 44, 39, 34, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 33, 35, 36,
	37, 38, 40, 41, 42, 43, 45, 47, 58, 59, 60, 61, 62, 63, 64, 91, 92, 93, 94,
	95, 96, 123, 124, 125, 126, 127, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
	13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142,
	143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157,
	158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172,
	173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187,
	188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202,
	203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217,
	218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232,
	233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247,
	248, 249, 250, 251, 252, 253, 254, 255,
}

type AttackFailedError string

func (e AttackFailedError) Error() string {
	return string(e)
}

// CrackECBOracleByteAtATime attempts to decrypt, without knowledge of the key,
// any data appended immediately after the user input by an encryption oracle
// using ECB mode, even if the oracle also prepends data to the user input.
//
// Note: There are simpler ways to implement this, but this function aims to
// perform the attack with as few calls to the oracle as possible.
func CrackECBOracleByteAtATime(maxBlockSize int, oracle EncryptionOracle) ([]byte, error) {
	blockSize, err := DetectOracleBlockSize(maxBlockSize, oracle)
	if err != nil {
		return nil, fmt.Errorf("detecting block size: %w", err)
	}

	ecbMode, err := IsOracleECBMode(blockSize, oracle)
	if err != nil {
		return nil, fmt.Errorf("detecting ECB mode: %w", err)
	}
	if !ecbMode {
		return nil, AttackFailedError("not ECB mode")
	}

	// Get the target ciphertext and a new oracle func that automatically
	// block-aligns our input and strips any unknown prefix data from the
	// output.
	var ciphertext []byte
	ciphertext, oracle, err = stripOraclePrefixBytes(blockSize, oracle)
	if err != nil {
		return nil, fmt.Errorf("attempting to strip any unknown input prefix bytes: %v", err)
	}

	// Generate a map relating duplicate ciphertext blocks so we can later avoid
	// re-decrypting them.
	refs, err := relateDuplicateBlocks(ciphertext, blockSize)
	if err != nil {
		return nil, fmt.Errorf("relating duplicate ciphertext blocks: %w", err)
	}

	// Generate the target blocks we will brute-force.
	blockBuf := make([]byte, blockSize)
	targetBlocks, err := generateTargetBlocks(blockBuf, len(ciphertext), oracle)
	if err != nil {
		return nil, fmt.Errorf("generating target blocks: %w", err)
	}

	var decrypted []byte
	for i := 0; i < len(targetBlocks); i++ {
		// Skip having to decrypt blocks for which we alredy know the plaintext.
		if i%blockSize == 0 {
			if j, ok := refs[i]; ok {
				decrypted = append(decrypted, decrypted[j:j+blockSize]...)
				i += blockSize - 1 // k - 1 due to the for clause's i++ post statement.
				continue
			}
		}

		if i < blockSize {
			copy(blockBuf[blockSize-1-i:], decrypted)
		} else {
			copy(blockBuf, decrypted[(i-blockSize)+1:])
		}

		var found bool
		for _, j := range byteSearchOrder {
			b := byte(j)
			blockBuf[blockSize-1] = b
			output, err := oracle(blockBuf)
			if err != nil {
				return nil, fmt.Errorf("querying encryption oracle with \"%x\": %w", blockBuf, err)
			}
			if found = bytes.Equal(targetBlocks[i], output[:blockSize]); found {
				decrypted = append(decrypted, b)
				break
			}
		}

		if !found {
			return decrypted, AttackFailedError("unable to decrypt byte at index " + strconv.Itoa(i))
		}
	}

	return decrypted, nil
}

// stripOraclePrefixBytes returns the ciphertext stripped of any unknown input
// prefix data and a new oracle func that wraps the original to automatically
// handle block-aligning input and stripping unknown prefix data from the
// output.
func stripOraclePrefixBytes(
	blockSize int,
	oracle EncryptionOracle,
) (strippedCiphertext []byte, strippingOracle EncryptionOracle, err error) {
	prefix := make([]byte, blockSize*2)
	for i := 0; i < blockSize; i++ {
		ciphertext, err := oracle(prefix)
		if err != nil {
			return nil, nil, fmt.Errorf("querying oracle with \"%x\": %v", prefix, err)
		}

		if len(ciphertext) == 0 {
			return ciphertext, oracle, nil
		}

		if len(ciphertext)%blockSize != 0 {
			return nil, nil, AttackFailedError(fmt.Sprintf("oracle returned ciphertext of invalid length %d", len(ciphertext)))
		}

		prev := ciphertext[:blockSize]
		for i, j := blockSize, 2*blockSize; j <= len(ciphertext); i, j = i+blockSize, j+blockSize {
			block := ciphertext[i:j]
			if bytes.Equal(prev, block) {
				return ciphertext[j:], newPrefixHandlingOracle(prefix, j, oracle), nil
			}
			prev = block
		}

		prefix = append(prefix, 0x00)
	}

	return nil, nil, AttackFailedError("unable to find start of target bytes")
}

// newPrefixHandlingOracle takes an EncryptionOracle and returns a new one that
// automatically prepends alignmentPrefix to oracle input and only returns
// ciphertext bytes >= targetStartIndex.
func newPrefixHandlingOracle(
	alignmentPrefix []byte,
	targetStartIndex int,
	oracle EncryptionOracle,
) EncryptionOracle {
	return func(input []byte) ([]byte, error) {
		input = append(alignmentPrefix, input...)
		ct, err := oracle(input)
		if err != nil {
			return nil, err
		}
		return ct[targetStartIndex:], nil
	}
}

// relateDuplicateBlocks creates a map relating the index of the first byte of
// one ciphertext block to the index of the first byte of another matching
// ciphertext block that came before it, for all blocks that have a prior
// duplicate. Therefore, given a ciphertext "XXXXABCDEFGHXXXXIJKLIJKLXXXX" and
// block size 4, relateDuplicateBlocks would return the mapping:
// { 12: 1, 20: 16, 24: 1 }.
func relateDuplicateBlocks(ciphertext []byte, blockSize int) (map[int]int, error) {
	refs := map[int]int{}
	seen := make(map[string]int, len(ciphertext)/blockSize)
	for i, j := 0, blockSize; j <= len(ciphertext); i, j = i+blockSize, j+blockSize {
		block := ciphertext[i:j]
		if v, ok := seen[string(block)]; ok {
			refs[i] = v
		} else {
			seen[string(block)] = i
		}
	}
	return refs, nil
}

// generateTargetBlocks generates one encrypted block of length
// k = len(initialBlock) for each byte of the underlying plaintext, minus
// padding, where the first k-1 plaintext bytes of each block match the last k-1
// plaintext bytes of the previous block, with initialBlock acting as the
// "previous" block for the first block. It is expected that len(initialBlock)
// is the block size used by encrypt.
//
// Given a initialBlock "xxxx" and a ciphertext of the plaintext "ABCDEF22",
// generateTargetBlocks would return ciphertext blocks of the following
// plaintexts:
//
//	["xxxA", "xxAB", "xABC", "ABCD", "BCDE", "CDEF"]
//
// This is done using k queries to encrypt, illustrated below in terms of the
// underlying plaintext.
//
//	encrypt("xxx") => xxxA BCDE F333*
//	encrypt("xx")  => xxAB CDEF 4444*
//	encrypt("x")   => xABC DEF1*
//	encrypt("")    => ABCD EF22*
//
// Where the last k blocks, marked with "*", are discarded.
func generateTargetBlocks(initialBlock []byte, lenCiphertext int, oracle EncryptionOracle) ([][]byte, error) {
	k := len(initialBlock)
	targets := make([][]byte, lenCiphertext+k)
	var n int
	for i := 0; i < k; i++ {
		output, err := oracle(initialBlock[:k-1-i])
		if err != nil {
			return nil, fmt.Errorf("querying encryption oracle with \"%x\": %w", initialBlock[:k-1-i], err)
		}
		for j := 0; j+k <= len(output); j += k {
			targets[i+j] = output[j : j+k]
			n++
		}
	}
	return targets[:n-k], nil
}
