package attack

type EncryptionOracle func(input []byte) (ciphertext []byte, err error)
