package main

import (
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

func taylor() {
	var start time.Time
	var err error

	// Schemes parameters are created from scratch
	params, err := ckks.NewParametersFromLiteral(
		ckks.ParametersLiteral{
			LogN:         13,
			LogQ:         []int{55, 40, 40, 40, 40, 40},
			LogP:         []int{45, 45},
			LogSlots:     13,
			RingType:     ring.ConjugateInvariant,
			DefaultScale: 1 << 45,
		})
	if err != nil {
		panic(err)
	}

	slots := params.Slots()
	logBatch := 0
	batch := 1 << logBatch
	n := slots / batch

	kgen := ckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()

	rlk := kgen.GenRelinearizationKey(sk, 1)
	rotKey := kgen.GenRotationKeysForRotations(params.RotationsForInnerSumLog(batch, n), false, sk)
	encryptor := ckks.NewEncryptor(params, pk)
	decryptor := ckks.NewDecryptor(params, sk)
	encoder := ckks.NewEncoder(params)
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotKey})

	values := make([]float64, slots)
	step := 1.0 / float64(slots-1)
	average := float64(0)
	for i := range values {
		values[i] = float64(i) * step
		average += values[i]
		if i < 16 || i > slots-16 {
			fmt.Printf("value[%d]: %f", i, values[i])
			fmt.Println()
		}
	}
	average /= float64(slots)

	plaintext := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())
	encoder.Encode(values, plaintext, params.LogSlots())
	fmt.Printf("Done in %s \n", time.Since(start))

	fmt.Println()
	fmt.Println("=========================================")
	fmt.Println("              ENCRYPTION & Taylor       ")
	fmt.Println("=========================================")
	fmt.Println()

	start = time.Now()
	ciphertext := encryptor.EncryptNew(plaintext) ////ciphertext

	coeffs := []complex128{
		complex(1.0, 0),
		complex(1.0, 0),
		complex(1.0/2, 0),
		complex(1.0/6, 0),
		complex(1.0/24, 0),
		complex(1.0/120, 0),
		complex(1.0/720, 0),
		complex(1.0/5040, 0),
	}

	poly := ckks.NewPoly(coeffs)

	if ciphertext, err = evaluator.EvaluatePoly(ciphertext, poly, ciphertext.Scale); err != nil {
		panic(err)
	}

	fmt.Println("=========================================")
	fmt.Println("         DECRYPTION & DECODING           ")
	fmt.Println("=========================================")
	fmt.Println()

	start = time.Now()
	decryptedResult := encoder.Decode(decryptor.DecryptNew(ciphertext), params.LogSlots())
	fmt.Printf("Total Slots: %d", slots)
	fmt.Println()

	for i := range decryptedResult {
		if i < 16 || i > slots-16 {
			fmt.Printf("decryptedResult[%d]: %f", i, real(decryptedResult[i]))
			fmt.Println()
		}
	}

	fmt.Printf("Done in %s \n", time.Since(start))
	fmt.Println()
}

func main() {
	ss := []int{9, 8, 7, 6, 5}
	sss := ss[2:3]
	fmt.Println("sss:")
	for i, _ := range sss {
		fmt.Println("%d", sss[i])
	}

	//taylor()
}
