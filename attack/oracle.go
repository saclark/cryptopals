package attack

type OracleEncryptFunc func(chosenPlaintext []byte) (ciphertext []byte, err error)
