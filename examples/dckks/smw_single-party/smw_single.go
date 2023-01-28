package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/drlwe"
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

// Check the result
const float64EqualityThreshold = 1e-4

var NGoRoutine int = 1 // Default number of Go routines

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) <= float64EqualityThreshold
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func runTimed(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

func runTimedParty(f func(), N int) time.Duration {
	start := time.Now()
	f()
	return time.Duration(time.Since(start).Nanoseconds() / int64(N))
}

type party struct {
	id          int
	folderName  string
	sk          *rlwe.SecretKey
	rlkEphemSk  *rlwe.SecretKey
	ckgShare    *drlwe.CKGShare
	rkgShareOne *drlwe.RKGShare
	rkgShareTwo *drlwe.RKGShare
	rtgShare    *drlwe.RTGShare
	pcksShare   *drlwe.PCKSShare

	input []float64
}

type task struct {
	wg          *sync.WaitGroup
	op1         *ckks.Ciphertext
	op2         *ckks.Ciphertext
	res         *ckks.Ciphertext
	elapsedtask time.Duration
}

var elapsedSKGParty time.Duration
var elapsedPKGParty time.Duration
var elapsedRKGParty time.Duration
var elapsedRTGParty time.Duration

var elapsedEncryptParty time.Duration
var elapsedDecParty time.Duration

var elapsedAddition time.Duration
var elapsedMultiplication time.Duration
var elapsedRotation time.Duration

var elapsedSummation time.Duration
var elapsedDeviation time.Duration

var pathFormat = "C:\\Users\\23304161\\source\\smw\\%s\\House_10sec_1month_%d.csv"

func main() {
	start := time.Now()

	loop := 10
	maximumLenPartyRows := 8640
	folderName := "200Houses_10s_1month_highVD"

	householdIDs := []int{}
	minHouseholdID := 1
	maxHouseholdID := 20

	for householdID := minHouseholdID; householdID <= maxHouseholdID; householdID++ {
		householdIDs = append(householdIDs, householdID)
	}

	var err error
	paramsDef := ckks.PN14QP438CI
	params, err := ckks.NewParametersFromLiteral(paramsDef)
	check(err)

	for i := 0; i < loop; i++ {
		process(householdIDs, maximumLenPartyRows, folderName, params)
	}

	fmt.Println("1~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	fmt.Printf("***** Evaluating Summation time for %d households in thirdparty analyst's side: %s\n", len(householdIDs), time.Duration(elapsedSummation.Nanoseconds()/int64(loop)))
	fmt.Printf("***** Evaluating Deviation time for %d households in thirdparty analyst's side: %s\n", len(householdIDs), time.Duration(elapsedDeviation.Nanoseconds()/int64(loop)))

	fmt.Println("2~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

	//public key & relinearization key & rotation key
	fmt.Printf("*****Amortized SKG Time: %s\n", time.Duration(elapsedSKGParty.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized PKG Time: %s\n", time.Duration(elapsedPKGParty.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized RKG Time: %s\n", time.Duration(elapsedRKGParty.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized RTG Time: %s\n", time.Duration(elapsedRTGParty.Nanoseconds()/int64(loop)))

	//single operation, independent of households' size
	fmt.Printf("*****Amortized Encrypt Time: %s\n", time.Duration(elapsedEncryptParty.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized Decrypt Time: %s\n", time.Duration(elapsedDecParty.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized Ciphertext Addition Time: %s\n", time.Duration(elapsedAddition.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized Ciphertext Multiplication Time: %s\n", time.Duration(elapsedMultiplication.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized Ciphertext Rotation Time: %s\n", time.Duration(elapsedRotation.Nanoseconds()/int64(loop*len(params.GaloisElementsForRowInnerSum()))))

	fmt.Printf("Main() Done in %s \n", time.Since(start))
}

//main start
func process(householdIDs []int, maximumLenPartyRows int, folderName string, params ckks.Parameters) {

	// For more details about the PSI example see
	//     Multiparty Homomorphic Encryption: From Theory to Practice (<https://eprint.iacr.org/2020/304>)
	l := log.New(os.Stderr, "", 0)

	// $go run main.go arg1 arg2
	// arg1: number of parties
	// arg2: number of Go routines

	// householdIDs := []int{6, 7, 8} // using suffix IDs of the csv files
	// Largest for n=8192: 512 parties

	// Target private and public keys
	tkgen := ckks.NewKeyGenerator(params)
	var tsk *rlwe.SecretKey
	var tpk *rlwe.PublicKey
	elapsedSKGParty += runTimed(func() {
		tsk = tkgen.GenSecretKey()
	})
	elapsedPKGParty += runTimed(func() {
		tpk = tkgen.GenPublicKey(tsk)
	})

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := genparties(params, folderName, householdIDs)

	// Inputs & expected result, cleartext result
	globalPartyRows, expSummation, expAverage, expDeviation := genInputs(params, P, maximumLenPartyRows) //globalPartyRows rows

	var rlk *rlwe.RelinearizationKey
	elapsedRKGParty += runTimed(func() {
		rlk = tkgen.GenRelinearizationKey(tsk, 1)
	})

	rotations := params.RotationsForInnerSumLog(1, globalPartyRows)
	var rotk *rlwe.RotationKeySet
	elapsedRTGParty += runTimed(func() {
		rotk = tkgen.GenRotationKeysForRotations(rotations, false, tsk)
	})

	decryptor := ckks.NewDecryptor(params, tsk)
	encoder := ckks.NewEncoder(params)
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotk})

	//generate ciphertexts
	encInputsAverage, encInputsNegative, encInputsSummation := encPhase(params, P, tpk, encoder)

	encSummationOuts := make([]*ckks.Ciphertext, 0)
	// encAverageOuts := make([]*ckks.Ciphertext, 0)
	encDeviationOuts := make([]*ckks.Ciphertext, 0)

	// summation
	for _, encInputSummation := range encInputsSummation {
		elapsedSummation += runTimed(func() {
			elapsedRotation += runTimedParty(func() {
				evaluator.InnerSumLog(encInputSummation, 1, params.Slots(), encInputSummation)
			}, len(P))
		})

		encSummationOuts = append(encSummationOuts, encInputSummation)
	}

	// deviation
	for i, encInputAverage := range encInputsAverage {
		elapsedDeviation += runTimed(func() {
			evaluator.InnerSumLog(encInputAverage, 1, params.Slots(), encInputAverage)
			encInputAverage.Scale *= float64(globalPartyRows) //each element contains the

			// encAverageOuts = append(encAverageOuts, encInputAverage)

			elapsedAddition += runTimedParty(func() {
				evaluator.Add(encInputsNegative[i], encInputAverage, encInputsNegative[i])
			}, len(P))

			elapsedMultiplication += runTimedParty(func() {
				evaluator.MulRelin(encInputsNegative[i], encInputsNegative[i], encInputsNegative[i])
			}, len(P))

			evaluator.InnerSumLog(encInputsNegative[i], 1, params.Slots(), encInputsNegative[i])
			encInputsNegative[i].Scale *= float64(globalPartyRows)
		})

		encDeviationOuts = append(encDeviationOuts, encInputsNegative[i])
	}

	// Decrypt & Check the result
	l.Println("> Decrypt & Result:>>>>>>>>>>>>>")

	ptres := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())
	ptresDeviation := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())
	ptresSummation := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())

	// print summation
	for i, _ := range encSummationOuts {
		decryptor.Decrypt(encSummationOuts[i], ptresSummation)            //ciphertext->plaintext
		resSummation := encoder.Decode(ptresSummation, params.LogSlots()) //plaintext->complex numbers
		fmt.Printf("CKKS Summation of Party[%d]=%.6f\t", i, real(resSummation[0]))
		fmt.Printf(" <===> Expected Summation of Party[%d]=%.6f\t", i, expSummation[i])
		fmt.Println()
	}

	// print deviation
	for i, _ := range encDeviationOuts {

		elapsedDecParty += runTimedParty(func() {
			// decryptor.Decrypt(encAverageOuts[i], ptres)            //ciphertext->plaintext
			decryptor.Decrypt(encDeviationOuts[i], ptresDeviation) //ciphertext->plaintext
		}, len(P))

		res := encoder.Decode(ptres, params.LogSlots())
		resDeviation := encoder.Decode(ptresDeviation, params.LogSlots())

		calculatedAverage := real(res[0])

		fmt.Printf("CKKS Average of Party[%d]=%.6f\t", i, calculatedAverage)
		fmt.Printf(" <===> Expected Average of Party[%d]=%.6f\t", i, expAverage[i])
		fmt.Println()

		//extra value for deviation
		delta := calculatedAverage * calculatedAverage * float64(len(resDeviation)-globalPartyRows) / float64(globalPartyRows)

		fmt.Printf("CKKS Deviation of Party[%d]=%.6f\t", i, real(resDeviation[0])-delta)
		fmt.Printf(" <===> Expected Deviation of Party[%d]=%.6f\t", i, expDeviation[i])
		fmt.Println()
	}

	fmt.Printf("\tDecrypt Time: done %s\n", elapsedDecParty)
	fmt.Println()

	//print result
	visibleNum := 4
	fmt.Println("> Parties:")
	//original data
	for i, pi := range P {
		fmt.Printf("Party %3d(%d):\t\t", i, len(pi.input))
		for j, element := range pi.input {
			if j < visibleNum || (j > globalPartyRows-visibleNum && j < globalPartyRows) {
				fmt.Printf("[%d]%.6f\t", j, element)
			}
		}
		fmt.Println()
	}
}

//main end

// encPhase to get []ciphertext
func encPhase(params ckks.Parameters, P []*party, pk *rlwe.PublicKey, encoder ckks.Encoder) (encInputsAverage, encInputsNegative, encInputsSummation []*ckks.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	encInputsAverage = make([]*ckks.Ciphertext, len(P))
	encInputsNegative = make([]*ckks.Ciphertext, len(P))
	encInputsSummation = make([]*ckks.Ciphertext, len(P))

	for i := range encInputsAverage {
		encInputsAverage[i] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
		encInputsNegative[i] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
		encInputsSummation[i] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
	}

	// Each party encrypts its input vector
	l.Println("> Encrypt Phase<<<<<<<<<<<<<<<<<<")
	encryptor := ckks.NewEncryptor(params, pk)
	pt := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())

	elapsedEncryptParty += runTimedParty(func() {
		for i, pi := range P {
			encoder.Encode(pi.input, pt, params.LogSlots())
			encryptor.Encrypt(pt, encInputsAverage[i])
			encryptor.Encrypt(pt, encInputsSummation[i])
			//turn pi.input to negative
			for j, _ := range pi.input {
				pi.input[j] *= -1
			}
			encoder.Encode(pi.input, pt, params.LogSlots())
			encryptor.Encrypt(pt, encInputsNegative[i])
			////turn pi.input to positive
			for j, _ := range pi.input {
				pi.input[j] *= -1
			}
		}
	}, 3*len(P)) //3 encryption in function

	l.Printf("\tdone  %s\n", elapsedEncryptParty)

	return
}

//generate parties
func genparties(params ckks.Parameters, folderName string, householdIDs []int) []*party {
	N := len(householdIDs)
	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := make([]*party, N)

	for i, id := range householdIDs {
		pi := &party{}
		pi.sk = ckks.NewKeyGenerator(params).GenSecretKey()
		pi.id = id
		pi.folderName = folderName

		P[i] = pi
	}

	return P
}

//file reading
func ReadCSV(path string) []string {
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

//trim csv
func resizeCSV(folderName string, id int) []float64 {

	path := fmt.Sprintf(pathFormat, folderName, id)
	csv := ReadCSV(path)

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

//generate inputs of parties
func genInputs(params ckks.Parameters, P []*party, maximumLenPartyRows int) (globalPartyRows int, expSummation, expAverage, expDeviation []float64) {

	globalPartyRows = -1
	for pi, po := range P {
		partyRows := resizeCSV(po.folderName, po.id)
		lenPartyRows := len(partyRows)
		if maximumLenPartyRows < lenPartyRows {
			lenPartyRows = maximumLenPartyRows
		}

		if globalPartyRows == -1 {
			//global setting, run once
			globalPartyRows = lenPartyRows
			expSummation = make([]float64, len(P))
			expAverage = make([]float64, len(P))
			expDeviation = make([]float64, len(P))
		} else if globalPartyRows != lenPartyRows {
			//make sure pi.input[] has the same size
			err := errors.New("Not all files have the same rows")
			check(err)
		}

		po.input = make([]float64, lenPartyRows)
		for i := range po.input {
			po.input[i] = partyRows[i]
			expSummation[pi] += po.input[i]
		}

		expAverage[pi] = expSummation[pi] / float64(globalPartyRows)

		for i := range po.input {
			temp := po.input[i] - expAverage[pi]
			expDeviation[pi] += temp * temp
		}

		expDeviation[pi] /= float64(globalPartyRows)
	}

	return
}
