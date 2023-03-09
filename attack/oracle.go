package attack

type EncryptionOracle func(chosenPlaintext []byte) (ciphertext []byte, err error)
