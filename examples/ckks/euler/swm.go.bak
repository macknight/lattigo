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

func ReadCSV() []string {
	fmt.Println("reading without buffer:")
	data, err := os.ReadFile("C:\\Users\\23304161\\source\\smw\\200Houses_10s_1month_highNE\\House_10sec_1month_1.csv")
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
func resizeCSV() []float64 {
	csv := ReadCSV()
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
	tmpArr := make([]float64, len(elements)/6)
	for i, _ := range tmpArr {
		tmpArr[i] = elements[i*6] + elements[i*6+1] + elements[i*6+2] + elements[i*6+3] + elements[i*6+4] + elements[i*6+5]
	}
	fmt.Println("resized CSV size:", len(tmpArr))
	return tmpArr
}

func main() {
	deviation()
}

func deviation() {
	var start time.Time
	var err error
	dataArray := resizeCSV()
	// Schemes parameters are created from scratch
	params, err := ckks.NewParametersFromLiteral(
		ckks.ParametersLiteral{
			LogN:         16,
			LogQ:         []int{55, 40, 40, 40, 40, 40, 40, 40, 40},
			LogP:         []int{45, 45},
			LogSlots:     16,
			RingType:     ring.ConjugateInvariant,
			DefaultScale: 1 << 45,
		})
	if err != nil {
		panic(err)
	}

	slots := params.Slots()
	fmt.Println("slots sie:", slots)
	// return
	logBatch := 0
	batch := 1 << logBatch //1
	n := slots / batch     //slots batches

	kgen := ckks.NewKeyGenerator(params)
	sk, pk := kgen.GenKeyPair()

	rlk := kgen.GenRelinearizationKey(sk, 1)
	rotKey := kgen.GenRotationKeysForRotations(params.RotationsForInnerSumLog(batch, n), false, sk)
	encryptor := ckks.NewEncryptor(params, pk)
	decryptor := ckks.NewDecryptor(params, sk)
	encoder := ckks.NewEncoder(params)
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotKey})

	values := make([]float64, slots)
	average := float64(0)
	lenDataArray := len(dataArray)
	for i := range values {
		if i < lenDataArray {
			values[i] = dataArray[i]
		} else {
			values[i] = 0
		}
		average += values[i]
	}
	average /= float64(slots)

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
	evaluator.Average(ciphertext, logBatch, ciphertext)

	//print out avarage:
	decryptedResult := encoder.Decode(decryptor.DecryptNew(ciphertext), params.LogSlots())
	fmt.Printf("CKKS Average: %f", real(decryptedResult[0]))
	fmt.Println()
	fmt.Printf("Arithmetic Average: %f", average)

	fmt.Println()
	fmt.Println("=========================================")
	fmt.Println("              NEGATIVE ELEMENTS          ")
	fmt.Println("=========================================")
	fmt.Println()

	for i := range values {
		values[i] *= -1
	}
	encoder.Encode(values, plaintext, params.LogSlots())
	ciphertext2 := encryptor.EncryptNew(plaintext) ////ciphertext2
	for i := range values {
		values[i] += average
	}

	fmt.Println()
	fmt.Println("=========================================")
	fmt.Println("              DEVIATION                  ")
	fmt.Println("=========================================")
	fmt.Println()
	start = time.Now()

	evaluator.Add(ciphertext, ciphertext2, ciphertext)
	evaluator.Power(ciphertext, int(2), ciphertext)
	evaluator.Average(ciphertext, logBatch, ciphertext)

	fmt.Printf("Done in %s \n", time.Since(start))
	deviation := float64(0)
	for i := range values {
		deviation += values[i] * values[i]
	}
	deviation /= float64(slots)

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
