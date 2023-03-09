package aes

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/saclark/cryptopals-go/pkcs7"
)

type OracleState struct {
	Mode                Mode
	Key                 []byte
	IV                  []byte
	PreProcessPlaintext func([]byte) ([]byte, error)
}

type OracleNewStateFunc func() (OracleState, error)

type Oracle struct {
	State    OracleState
	newState OracleNewStateFunc
}

func NewOracle(newState OracleNewStateFunc) Oracle {
	return Oracle{newState: newState}
}

type OracleEncryptFunc func(plaintext []byte) ([]byte, error)

func (o *Oracle) Encrypt(plaintext []byte) ([]byte, error) {
	var err error
	if o.State, err = o.newState(); err != nil {
		return nil, fmt.Errorf("generating new state: %w", err)
	}

	input := make([]byte, len(plaintext))
	copy(input, plaintext)

	if o.State.PreProcessPlaintext != nil {
		if input, err = o.State.PreProcessPlaintext(input); err != nil {
			return nil, fmt.Errorf("pre-processing plaintext: %w", err)
		}
	}

	if o.State.Mode == ModeECB {
		return EncryptECB(input, o.State.Key)
	}

	return EncryptCBC(input, o.State.Key, o.State.IV)
}

func NewPrependableECBOracleState(internalPlaintext []byte) (OracleState, error) {
	key, err := randomBlock(BlockSize)
	if err != nil {
		return OracleState{}, fmt.Errorf("generating random key: %w", err)
	}
	state := OracleState{
		Mode: ModeECB,
		Key:  key,
		PreProcessPlaintext: func(plaintext []byte) ([]byte, error) {
			plaintext = append(plaintext, internalPlaintext...)
			return pkcs7.Pad(plaintext, BlockSize), nil
		},
	}
	return state, nil
}

func NewRandomOracleState() (OracleState, error) {
	var err error
	state := OracleState{
		PreProcessPlaintext: junkifyAndPad,
	}
	if state.Key, err = randomBlock(BlockSize); err != nil {
		return OracleState{}, fmt.Errorf("generating random key: %w", err)
	}
	if state.Mode, err = randomMode(); err != nil {
		return OracleState{}, fmt.Errorf("choosing random mode: %w", err)
	}
	if state.Mode == ModeCBC {
		if state.IV, err = randomBlock(BlockSize); err != nil {
			return OracleState{}, fmt.Errorf("generating random IV: %v", err)
		}
	}
	return state, nil
}

func randomBlock(blockSize int) ([]byte, error) {
	block := make([]byte, blockSize)
	if _, err := rand.Read(block); err != nil {
		return nil, fmt.Errorf("reading %d random bytes: %v", blockSize, err)
	}
	return block, nil
}

func randomMode() (Mode, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return 0, fmt.Errorf("generating random int in range [0, 2): %v", err)
	}
	if n.Int64() == 0 {
		return ModeECB, nil
	}
	return ModeCBC, nil
}

func junkifyAndPad(plaintext []byte) ([]byte, error) {
	randInt, err := rand.Int(rand.Reader, big.NewInt(6))
	if err != nil {
		return nil, fmt.Errorf("generating random int in range [0,6): %v", err)
	}

	n := int(randInt.Int64() + 5)
	b := byte(n)

	junkified := make([]byte, len(plaintext)+n*2)
	for i := 0; i < n; i++ {
		junkified[i], junkified[len(junkified)-1-i] = b, b
	}

	copy(junkified[n:len(junkified)-n], plaintext)

	return pkcs7.Pad(junkified, BlockSize), nil
}
