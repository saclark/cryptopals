package attack

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/saclark/cryptopals-go/aes"
	"github.com/saclark/cryptopals-go/pkcs7"
)

type AESOracleState struct {
	Mode                      Mode
	Key                       []byte
	IV                        []byte
	PreProcessChosenPlaintext func(chosenPlaintext []byte) (newChosenPlaintext []byte, err error)
}

type AESOracle struct {
	State    AESOracleState
	newState func() (AESOracleState, error)
}

func NewAESOracle(newState func() (AESOracleState, error)) AESOracle {
	return AESOracle{newState: newState}
}

func (o *AESOracle) Encrypt(chosenPlaintext []byte) ([]byte, error) {
	var err error
	if o.State, err = o.newState(); err != nil {
		return nil, fmt.Errorf("generating new state: %w", err)
	}

	cp := make([]byte, len(chosenPlaintext))
	copy(cp, chosenPlaintext)

	if o.State.PreProcessChosenPlaintext != nil {
		if cp, err = o.State.PreProcessChosenPlaintext(cp); err != nil {
			return nil, fmt.Errorf("pre-processing plaintext: %w", err)
		}
	}

	if o.State.Mode == ModeECB {
		return aes.EncryptECB(cp, o.State.Key)
	}

	return aes.EncryptCBC(cp, o.State.Key, o.State.IV)
}

func NewPrependableECBAESOracleState(hiddenPlaintext []byte) (AESOracleState, error) {
	key, err := randomBlock()
	if err != nil {
		return AESOracleState{}, fmt.Errorf("generating random key: %w", err)
	}
	state := AESOracleState{
		Mode: ModeECB,
		Key:  key,
		PreProcessChosenPlaintext: func(chosenPlaintext []byte) ([]byte, error) {
			chosenPlaintext = append(chosenPlaintext, hiddenPlaintext...)
			return pkcs7.Pad(chosenPlaintext, aes.BlockSize), nil
		},
	}
	return state, nil
}

func NewRandomAESOracleState() (AESOracleState, error) {
	var err error
	state := AESOracleState{
		PreProcessChosenPlaintext: junkifyAndPad,
	}
	if state.Key, err = randomBlock(); err != nil {
		return AESOracleState{}, fmt.Errorf("generating random key: %w", err)
	}
	if state.Mode, err = randomMode(); err != nil {
		return AESOracleState{}, fmt.Errorf("choosing random mode: %w", err)
	}
	if state.Mode == ModeCBC {
		if state.IV, err = randomBlock(); err != nil {
			return AESOracleState{}, fmt.Errorf("generating random IV: %v", err)
		}
	}
	return state, nil
}

func randomBlock() ([]byte, error) {
	block := make([]byte, aes.BlockSize)
	if _, err := rand.Read(block); err != nil {
		return nil, fmt.Errorf("reading %d random bytes: %v", aes.BlockSize, err)
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

func junkifyAndPad(chosenPlaintext []byte) ([]byte, error) {
	randInt, err := rand.Int(rand.Reader, big.NewInt(6))
	if err != nil {
		return nil, fmt.Errorf("generating random int in range [0,6): %v", err)
	}

	n := int(randInt.Int64() + 5)
	b := byte(n)

	junkified := make([]byte, len(chosenPlaintext)+n*2)
	for i := 0; i < n; i++ {
		junkified[i], junkified[len(junkified)-1-i] = b, b
	}

	copy(junkified[n:len(junkified)-n], chosenPlaintext)

	return pkcs7.Pad(junkified, aes.BlockSize), nil
}
