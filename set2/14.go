// # Byte-at-a-time ECB decryption (Harder)
//
// Take your oracle function from #12. Now generate a random count of random
// bytes and prepend this string to every plaintext. You are now doing:
//
// 	AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
//
// Same goal: decrypt the target-bytes.
//
// > # Stop and think for a second.
// > What's harder than challenge #12 about doing this? How would you overcome
// > that obstacle? The hint is: you're using all the tools you already have;
// > no crazy math is required.
// >
// > Think "STIMULUS" and "RESPONSE".

package set2

import (
	"github.com/saclark/cryptopals/attack"
)

func CrackInputSandwichingECBOracle(maxBlockSize int, oracle func([]byte) ([]byte, error)) ([]byte, error) {
	return attack.CrackECBOracleByteAtATime(maxBlockSize, oracle)
}
