package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

func ReadCSV2(path string) []string {
	fmt.Println("reading without buffer:")
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	// fmt.Println("data:", string(data))
	dArray := strings.Split(string(data), "\n")
	fmt.Println("original CSV size:", len(dArray))
	dArray2 := dArray[1 : len(dArray)-1]
	fmt.Println("data CSV size:", len(dArray2)) //[0]..[241919]
	return dArray2
}

func resizeCSV2() []float64 {
	pathFormat := "C:\\Users\\23304161\\source\\smw\\%s\\House_10sec_1month_%d.csv"
	folderName := "200Houses_10s_1month_highNE"
	id := 1

	path := fmt.Sprintf(pathFormat, folderName, id)
	csv := ReadCSV2(path)

	elements := []float64{}
	for _, v := range csv {
		slices := strings.Split(v, ",")
		tmpStr := slices[len(slices)-1]
		fNum, err := strconv.ParseFloat(tmpStr, 64)
		if err != nil {
			panic(err)
		}
		elements = append(elements, fNum)
	}

	return elements
}

func main() {
	fmt.Println("deviation2")
	deviation2()
}

func deviation2() {

	var start time.Time
	var err error
	values := resizeCSV2()
	lenValues := len(values)
	// Schemes parameters are created from scratch
	params, err := ckks.NewParametersFromLiteral(
		ckks.ParametersLiteral{
			LogN:         18,
			LogQ:         []int{55, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40},
			LogP:         []int{45, 45},
			LogSlots:     18,
			RingType:     ring.ConjugateInvariant,
			DefaultScale: 1 << 45,
		})
	if err != nil {
		panic(err)
	}

	// return
	logBatch := 0
	batch := 1 << logBatch //1 batch size
	n := lenValues / batch //n batches

	kgen := ckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()

	rlk := kgen.GenRelinearizationKey(sk, 1)
	rotations := params.RotationsForInnerSumLog(batch, n)
	// fmt.Println("rotations:", len(rotations))
	// for _, r := range rotations {
	// 	fmt.Println(r)
	// }

	// return
	rotKey := kgen.GenRotationKeysForRotations(rotations, false, sk)
	encryptor := ckks.NewEncryptor(params, pk)
	decryptor := ckks.NewDecryptor(params, sk)
	encoder := ckks.NewEncoder(params)
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotKey})

	average := float64(0)
	for i := range values {
		average += values[i]
	}
	average /= float64(lenValues)

	plaintext := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())
	encoder.Encode(values, plaintext, params.LogSlots())
	fmt.Printf("Done in %s \n", time.Since(start))

	fmt.Println()
	fmt.Println("=========================================")
	fmt.Println("              ENCRYPTION & AVERAGE       ")
	fmt.Println("=========================================")
	fmt.Println()

	start = time.Now()
	ciphertext := encryptor.EncryptNew(plaintext) ////ciphertext
	//average for vector whose elements number is a power of non-2
	fmt.Println("level:", ciphertext.Level())
	fmt.Println("batch", batch)
	fmt.Println("n", n)
	evaluator.InnerSumLog(ciphertext, batch, n, ciphertext)
	//manually multiply ciphertext.Scale by 1/len(values)
	ciphertext.Scale *= float64(len(values))
	fmt.Println("level:", ciphertext.Level())
	//print out avarage:
	decryptedResult := encoder.Decode(decryptor.DecryptNew(ciphertext), params.LogSlots())
	fmt.Printf("CKKS Average: %f", real(decryptedResult[0]))
	fmt.Println()
	fmt.Printf("CKKS Average: %f", real(decryptedResult[1]))
	fmt.Println()
	fmt.Printf("CKKS Average: %f", real(decryptedResult[2]))
	fmt.Println()
	fmt.Printf("CKKS Average: %f", real(decryptedResult[3]))
	fmt.Println()
	fmt.Printf("CKKS Average: %f", real(decryptedResult[4]))
	fmt.Println()
	fmt.Printf("CKKS Average: %f", real(decryptedResult[5]))
	fmt.Println()
	fmt.Printf("CKKS Average: %f", real(decryptedResult[6]))
	fmt.Println()
	fmt.Printf("CKKS Average: %f", real(decryptedResult[7]))
	fmt.Println()

	fmt.Printf("Arithmetic Average: %f", average)
	///////////////////////////////////////////////////////////////////
	fmt.Println()
	fmt.Println("=========================================")
	fmt.Println("              NEGATIVE ELEMENTS          ")
	fmt.Println("=========================================")
	fmt.Println()

	for i := range values {
		values[i] *= -1
	}
	encoder.Encode(values, plaintext, params.LogSlots())
	ciphertext2 := encryptor.EncryptNew(plaintext) ////ciphertext2 = -values[i]
	for i := range values {
		values[i] += average
	}

	fmt.Println()
	fmt.Println("=========================================")
	fmt.Println("              DEVIATION                  ")
	fmt.Println("=========================================")
	fmt.Println()
	start = time.Now()

	fmt.Println("level:", ciphertext.Level())
	evaluator.Add(ciphertext, ciphertext2, ciphertext) // average - values[i]
	evaluator.Power(ciphertext, int(2), ciphertext)
	//average for vector whose elements number is a power of non-2
	evaluator.InnerSumLog(ciphertext, batch, n, ciphertext)
	//manually multiply ciphertext.Scale by 1/len(values)
	ciphertext.Scale *= float64(len(values))
	fmt.Println("level:", ciphertext.Level())
	fmt.Printf("Done in %s \n", time.Since(start))
	deviation := float64(0)
	for i := range values {
		deviation += values[i] * values[i]
	}
	deviation /= float64(lenValues)

	fmt.Println("=========================================")
	fmt.Println("         DECRYPTION & DECODING           ")
	fmt.Println("=========================================")
	fmt.Println()

	start = time.Now()
	decryptedResult = encoder.Decode(decryptor.DecryptNew(ciphertext), params.LogSlots())

	fmt.Printf("Done in %s \n", time.Since(start))
	fmt.Println()
	fmt.Printf("CKKS Deviation: %f", real(decryptedResult[0]))
	fmt.Println()
	fmt.Printf("Arithmetic Deviation: %f", deviation)
	fmt.Println()
}
