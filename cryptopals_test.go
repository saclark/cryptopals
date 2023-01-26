package cryptopals

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"github.com/saclark/cryptopals-go/aes"
	"github.com/saclark/cryptopals-go/xor"
)

func hexMustDecodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func base64MustDecodeString(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestChallenge1(t *testing.T) {
	input := hexMustDecodeString("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	got := base64.StdEncoding.EncodeToString(input)
	if want != got {
		t.Errorf("want: '%s', got: '%s'", want, got)
	}
}

func TestChallenge2(t *testing.T) {
	inputA := hexMustDecodeString("1c0111001f010100061a024b53535009181c")
	inputB := hexMustDecodeString("686974207468652062756c6c277320657965")
	want := "746865206b696420646f6e277420706c6179"

	xoredBytes := xor.FixedXOR(inputA, inputB)

	got := hex.EncodeToString(xoredBytes)
	if want != got {
		t.Errorf("want: '%s', got: '%s'", want, got)
	}
}

func TestChallenge3(t *testing.T) {
	input := hexMustDecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	want := "Cooking MC's like a pound of bacon"

	key, _ := xor.DetectRepeatingByteXORKey(input)
	plaintext := xor.RepeatingByteXOR(input, key)

	got := string(plaintext)
	if want != got {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}

func TestChallenge4(t *testing.T) {
	inputFile := "data/4.txt"
	want := "Now that the party is jumping\n"

	file, err := os.Open(inputFile)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	var score float64
	var plaintext []byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := hexMustDecodeString(scanner.Text())
		key, s := xor.DetectRepeatingByteXORKey(line)
		if s >= score {
			score = s
			plaintext = xor.RepeatingByteXOR(line, key)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	got := string(plaintext)
	if want != got {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}

func TestChallenge5(t *testing.T) {
	input := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")
	want := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	encrypted := xor.RepeatingXOR(input, key)

	got := hex.EncodeToString(encrypted)
	if want != got {
		t.Errorf("\nwant: '%s'\ngot : '%s'", want, got)
	}
}

func TestChallenge6(t *testing.T) {
	inputFile := "data/6.txt"
	want := "Terminator X: Bring the noise"

	b, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatal(err)
	}
	b = base64MustDecodeString(string(b))

	key, _ := xor.DetectRepeatingXORKey(b, 2, 40, 12)

	got := string(key)
	if want != got {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}

func TestChallenge7(t *testing.T) {
	inputFile := "data/7.txt"
	key := []byte("YELLOW SUBMARINE")
	//lint:ignore ST1018 the result ends with a few errant bytes for some reason
	want := `I'm back and I'm ringin' the bell 
A rockin' on the mike while the fly girls yell 
In ecstasy in the back of me 
Well that's my DJ Deshay cuttin' all them Z's 
Hittin' hard and the girlies goin' crazy 
Vanilla's on the mike, man I'm not lazy. 

I'm lettin' my drug kick in 
It controls my mouth and I begin 
To just let it flow, let my concepts go 
My posse's to the side yellin', Go Vanilla Go! 

Smooth 'cause that's the way I will be 
And if you don't give a damn, then 
Why you starin' at me 
So get off 'cause I control the stage 
There's no dissin' allowed 
I'm in my own phase 
The girlies sa y they love me and that is ok 
And I can dance better than any kid n' play 

Stage 2 -- Yea the one ya' wanna listen to 
It's off my head so let the beat play through 
So I can funk it up and make it sound good 
1-2-3 Yo -- Knock on some wood 
For good luck, I like my rhymes atrocious 
Supercalafragilisticexpialidocious 
I'm an effect and that you can bet 
I can take a fly girl and make her wet. 

I'm like Samson -- Samson to Delilah 
There's no denyin', You can try to hang 
But you'll keep tryin' to get my style 
Over and over, practice makes perfect 
But not if you're a loafer. 

You'll get nowhere, no place, no time, no girls 
Soon -- Oh my God, homebody, you probably eat 
Spaghetti with a spoon! Come on and say it! 

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino 
Intoxicating so you stagger like a wino 
So punks stop trying and girl stop cryin' 
Vanilla Ice is sellin' and you people are buyin' 
'Cause why the freaks are jockin' like Crazy Glue 
Movin' and groovin' trying to sing along 
All through the ghetto groovin' this here song 
Now you're amazed by the VIP posse. 

Steppin' so hard like a German Nazi 
Startled by the bases hittin' ground 
There's no trippin' on mine, I'm just gettin' down 
Sparkamatic, I'm hangin' tight like a fanatic 
You trapped me once and I thought that 
You might have it 
So step down and lend me your ear 
'89 in my time! You, '90 is my year. 

You're weakenin' fast, YO! and I can tell it 
Your body's gettin' hot, so, so I can smell it 
So don't be mad and don't be sad 
'Cause the lyrics belong to ICE, You can call me Dad 
You're pitchin' a fit, so step back and endure 
Let the witch doctor, Ice, do the dance to cure 
So come up close and don't be square 
You wanna battle me -- Anytime, anywhere 

You thought that I was weak, Boy, you're dead wrong 
So come on, everybody and sing this song 

Say -- Play that funky music Say, go white boy, go white boy go 
play that funky music Go white boy, go white boy, go 
Lay down and boogie and play that funky music till you die. 

Play that funky music Come on, Come on, let me hear 
Play that funky music white boy you say it, say it 
Play that funky music A little louder now 
Play that funky music, white boy Come on, Come on, Come on 
Play that funky music 
`

	ciphertext, err := os.ReadFile(inputFile)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext = base64MustDecodeString(string(ciphertext))

	plaintext, err := aes.DecryptAESECB(ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}

	got := string(plaintext)
	if want != got {
		t.Errorf("want: '%x', got: '%x'", want, got)
	}
}
