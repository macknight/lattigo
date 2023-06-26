package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lazybeaver/entropy"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

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

	rawInput   []float64   //all data
	input      [][]float64 //data of encryption
	plainInput []float64   //data of plain
	flag       []int
	group      []int
	entropy    []float64
}

type task struct {
	wg          *sync.WaitGroup
	op1         *rlwe.Ciphertext
	op2         *rlwe.Ciphertext
	res         *rlwe.Ciphertext
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

var elapsedAnalystSummation time.Duration
var elapsedAnalystVariance time.Duration

// var pathFormat = "./%s/House_10sec_1month_%d.csv"
var pathFormat = "C:\\Users\\23304161\\source\\Datasets\\electricity\\archive\\%s\\House_1min_halfyear_%d.csv"
var folderName = "200Houses_10s_1month_lowVD"

const float64EqualityThreshold = 1e-0
const sectionSize = 4096 // element number within a section
var sectionNum = 0

var NGoRoutine int = 1 // Default number of Go routines
var flagCount = 0      // encrypted section number
var loop = 1

var attackLoop = 1000
var maximumLenPartyRows = 241920
var minHouseholdID = 1
var maxHouseholdID = 20
var encryptedSectionNum = 20 // from 0 to 60

func main() {
	rand.Seed(time.Now().UnixNano())

	start := time.Now()

	householdIDs := []int{}

	for householdID := minHouseholdID; householdID <= maxHouseholdID; householdID++ {
		householdIDs = append(householdIDs, householdID)
	}

	var err error
	paramsDef := ckks.PN12QP109CI // block size = 4096
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

	fmt.Printf("*****Amortized Analyst Time: %s\n", time.Duration(elapsedAnalystSummation.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized Analyst Time: %s\n", time.Duration(elapsedAnalystVariance.Nanoseconds()/int64(loop)))

	fmt.Printf("Main() Done in %s \n", time.Since(start))

	PrintMemUsage()
}

//main start
func process(householdIDs []int, maximumLenPartyRows int, folderName string, params ckks.Parameters) {
	fmt.Println("process:")
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

	//getInputs==================================================================
	// Inputs & expected result, cleartext result
	globalPartyRows, expSummation, expAverage, expDeviation, plainSum := genInputs(params, P, maximumLenPartyRows) //globalPartyRows rows

	//member identification attack

	var attackSuccessNum int
	for a := 0; a < attackLoop; a++ {
		attackSuccessNum += attackParties(P)
	}
	fmt.Printf("<<<<<<<<<<<EncryptedSectionNum = %v, ASR = %.3f\n", encryptedSectionNum, float64(attackSuccessNum)/float64(attackLoop))

	var rlk *rlwe.RelinearizationKey
	elapsedRKGParty += runTimed(func() {
		rlk = tkgen.GenRelinearizationKey(tsk, 1)
	})

	rotations := params.RotationsForInnerSum(1, globalPartyRows)
	var rotk *rlwe.RotationKeySet
	elapsedRTGParty += runTimed(func() {
		rotk = tkgen.GenRotationKeysForRotations(rotations, false, tsk)
	})

	decryptor := ckks.NewDecryptor(params, tsk)
	encoder := ckks.NewEncoder(params)
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotk})

	//generate ciphertexts==================================================================
	encInputsNegative, encInputsSummation := encPhase(params, P, tpk, encoder)

	// summation
	encSummationOuts := make([]*rlwe.Ciphertext, 0)
	anaTime1 := time.Now()
	var tmpCiphertext *rlwe.Ciphertext
	for i, encInputSummation := range encInputsSummation {
		if i%encryptedSectionNum == 0 {
			tmpCiphertext = encInputSummation
		} else {
			elapsedSummation += runTimed(func() {
				elapsedRotation += runTimedParty(func() {
					evaluator.Add(tmpCiphertext, encInputSummation, tmpCiphertext)
					if i%encryptedSectionNum == encryptedSectionNum-1 {
						evaluator.InnerSum(tmpCiphertext, 1, params.Slots(), tmpCiphertext)
					}
				}, len(P))
			})
		}
		if i%encryptedSectionNum == encryptedSectionNum-1 {
			encSummationOuts = append(encSummationOuts, tmpCiphertext)
			// encSummationOuts[i/encryptedSectionNum] = tmpCiphertext
		}
	}
	elapsedAnalystSummation += time.Since(anaTime1)

	// deviation
	encDeviationOuts := make([]*rlwe.Ciphertext, 0)
	anaTime2 := time.Now()
	for i, encInputNegative := range encInputsNegative {
		if i%encryptedSectionNum == 0 {
			tmpCiphertext = encSummationOuts[i/encryptedSectionNum].CopyNew()
			tmpCiphertext.Scale = tmpCiphertext.Mul(rlwe.NewScale(globalPartyRows))
		}
		elapsedDeviation += runTimed(func() {
			// encAverageOuts = append(encAverageOuts, encInputAverage)
			elapsedAddition += runTimedParty(func() {
				evaluator.Add(encInputNegative, tmpCiphertext, encInputNegative)
			}, len(P))

			elapsedMultiplication += runTimedParty(func() {
				evaluator.MulRelin(encInputNegative, encInputNegative, encInputNegative)
			}, len(P))

			if i%encryptedSectionNum == 0 {
				tmpCiphertext = encInputNegative
			} else {
				elapsedSummation += runTimed(func() {
					elapsedRotation += runTimedParty(func() {
						evaluator.Add(tmpCiphertext, encInputNegative, tmpCiphertext)
						if i%encryptedSectionNum == encryptedSectionNum-1 {
							evaluator.InnerSum(tmpCiphertext, 1, params.Slots(), tmpCiphertext)
							tmpCiphertext.Scale = tmpCiphertext.Mul(rlwe.NewScale(globalPartyRows))
						}
					}, len(P))
				})
			}
			if i%encryptedSectionNum == encryptedSectionNum-1 {
				encDeviationOuts = append(encDeviationOuts, tmpCiphertext)
				// encDeviationOuts[i/encryptedSectionNum] = tmpCiphertext
			}
		})
	}
	elapsedAnalystVariance += time.Since(anaTime2)

	// Decrypt & Check the result
	l.Println("> Decrypt & Result:>>>>>>>>>>>>>")

	// print summation
	ptresSummation := ckks.NewPlaintext(params, params.MaxLevel())
	for i, _ := range encSummationOuts {
		decryptor.Decrypt(encSummationOuts[i], ptresSummation)            //ciphertext->plaintext
		resSummation := encoder.Decode(ptresSummation, params.LogSlots()) //plaintext->complex numbers
		fmt.Printf("CKKS Summation of Party[%d]=%.6f\t", i, real(resSummation[0])+plainSum[i])
		fmt.Printf(" <===> Expected Summation of Party[%d]=%.6f\t", i, expSummation[i])
		fmt.Println()
	}

	// print deviation
	ptresDeviation := ckks.NewPlaintext(params, params.MaxLevel())
	for i, _ := range encDeviationOuts {

		elapsedDecParty += runTimedParty(func() {
			// decryptor.Decrypt(encAverageOuts[i], ptres)            //ciphertext->plaintext
			decryptor.Decrypt(encDeviationOuts[i], ptresDeviation) //ciphertext->plaintext
		}, len(P))

		// res := encoder.Decode(ptres, params.LogSlots())
		resDeviation := encoder.Decode(ptresDeviation, params.LogSlots())

		// calculatedAverage := real(res[0])
		calculatedAverage := expAverage[i]

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
	// visibleNum := 4
	fmt.Println("> Parties:")
	//original data
	// for i, pi := range P {
	// 	fmt.Printf("Party %3d(%d):\t\t", i, len(pi.input))
	// 	for j, element := range pi.input {
	// 		if j < visibleNum || (j > globalPartyRows-visibleNum && j < globalPartyRows) {
	// 			fmt.Printf("[%d]%.6f\t", j, element)
	// 		}
	// 	}
	// 	fmt.Println()
	// }
}

//main end

func encPhase(params ckks.Parameters, P []*party, pk *rlwe.PublicKey, encoder ckks.Encoder) (encInputsNegative, encInputsSummation []*rlwe.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	encInputsNegative = make([]*rlwe.Ciphertext, len(P)*encryptedSectionNum)
	encInputsSummation = make([]*rlwe.Ciphertext, len(P)*encryptedSectionNum)

	for i := range encInputsSummation {
		encInputsNegative[i] = ckks.NewCiphertext(params, 1, params.MaxLevel())
		encInputsSummation[i] = ckks.NewCiphertext(params, 1, params.MaxLevel())
	}

	// Each party encrypts its input vector
	l.Println("> Encrypt Phase<<<<<<<<<<<<<<<<<<")
	encryptor := ckks.NewEncryptor(params, pk)
	pt := ckks.NewPlaintext(params, params.MaxLevel())

	elapsedEncryptParty += runTimedParty(func() {
		for i, pi := range P {
			for j, _ := range pi.input {
				encoder.Encode(pi.input[j], pt, params.LogSlots())
				encryptor.Encrypt(pt, encInputsSummation[i*encryptedSectionNum+j]) //Encrypt
				//turn pi.input to negative
				for s, _ := range pi.input {
					for t, _ := range pi.input[s] {
						pi.input[s][t] *= -1
					}
				}
				encoder.Encode(pi.input[j], pt, params.LogSlots())
				encryptor.Encrypt(pt, encInputsNegative[i*encryptedSectionNum+j]) //Encrypt
				////turn pi.input to positive
				for s, _ := range pi.input {
					for t, _ := range pi.input[s] {
						pi.input[s][t] *= -1
					}
				}
			}
		}
	}, 2*len(P)) //3 encryption in function

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
	// fmt.Println("reading without buffer:")
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	// fmt.Println("data:", string(data))
	dArray := strings.Split(string(data), "\n")
	// fmt.Println("original CSV size:", len(dArray))
	dArray2 := dArray[1 : len(dArray)-1]
	// fmt.Println("data CSV size:", len(dArray2)) //[0]..[241919]
	return dArray2
}

//trim csv
func resizeCSV(folderName string, id int) []float64 {

	path := fmt.Sprintf(pathFormat, folderName, id)
	csv := ReadCSV(path)

	elements := []float64{}
	for _, v := range csv {
		slices := strings.Split(v, ",")
		tmpStr := strings.Replace(slices[len(slices)-1], "\r", "", -1)
		fNum, err := strconv.ParseFloat(tmpStr, 64)
		if err != nil {
			panic(err)
		}
		elements = append(elements, fNum)
	}

	return elements
}

func getRandom(numberRange int) (randNumber int) {
	randNumber = rand.Intn(numberRange) //[0, numberRange-1]
	return
}

func filterParties(P []*party, arr []float64) (resultParties []*party) {
	resultParties = make([]*party, 0)

	for _, po := range P {
		matched := false
		for i := 0; i < len(po.plainInput)-len(arr); i++ {
			for k := 0; k < len(arr); k++ {
				if po.plainInput[i+k] != arr[k] {
					break
				}
				matched = true
			}
			if matched {
				break
			}
		}
		if matched {
			resultParties = append(resultParties, po)
		}
	} // each party
	return
}

func attackParties(P []*party) (attackSuccessNum int) {
	fmt.Println("starting attack>>>>>>>>>>>>>")
	attackSuccessNum = 0
	randomParty := getRandom(maxHouseholdID)
	randomStart := getRandom(maximumLenPartyRows - sectionSize)
	fmt.Printf("attackering at Party[%d], position[%d]\n", randomParty, randomStart)

	// attackBlock := make([]float64, sectionSize)
	var leftArr []float64
	var rightArr []float64
	for k := 1; k < sectionSize-1; k++ {
		leftArr = make([]float64, 0)
		rightArr = make([]float64, 0)
		fmt.Printf("****divide at position: %d\n", k)
		var tmpParties []*party
		//search with left part
		for i := 0; i < k; i++ {
			leftArr = append(leftArr, P[randomParty].rawInput[i+randomStart])
		}
		// fmt.Printf("leftArrLen: %v\n", len(leftArr))
		tmpParties = filterParties(P, leftArr)

		if len(tmpParties) == 0 {
			// fmt.Printf("tmpParties size: %v\n", len(tmpParties))
			tmpParties = P
		}
		// fmt.Printf("new tmpParties size: %v\n", len(tmpParties))

		//search with right part
		for j := k; j < sectionSize; j++ {
			rightArr = append(rightArr, P[randomParty].rawInput[j+randomStart])
		}
		// fmt.Printf("rightArrLen: %v\n", len(rightArr))
		tmpParties = filterParties(tmpParties, rightArr)
		if len(tmpParties) == 1 {
			attackSuccessNum = 1
			fmt.Printf("!!!Success with party file[%d]\n", tmpParties[0].id)
			break
		}
	}
	fmt.Println("ending attack#############")
	return
}

func genInputs(params ckks.Parameters, P []*party, maximumLenPartyRows int) (globalPartyRows int, expSummation, expAverage, expDeviation, plainSum []float64) {
	fmt.Println("genInputs:")
	// randNumber := -1
	globalPartyRows = -1
	for pi, po := range P {
		partyRows := resizeCSV(po.folderName, po.id)
		lenPartyRows := len(partyRows)
		if maximumLenPartyRows < lenPartyRows {
			lenPartyRows = maximumLenPartyRows
		}

		if globalPartyRows == -1 {
			sectionNum = lenPartyRows / sectionSize
			if lenPartyRows%sectionSize != 0 {
				sectionNum++
			}
			// randNumber = getRandom(sectionSize) //[0, randNumber-1]
			// if randNumber == 0 {
			// 	randNumber = 1 //at least 1
			// }
			//global setting, run once
			globalPartyRows = lenPartyRows
			expSummation = make([]float64, len(P))
			expAverage = make([]float64, len(P))
			expDeviation = make([]float64, len(P))
			plainSum = make([]float64, len(P))
		} else if globalPartyRows != lenPartyRows {
			//make sure pi.input[] has the same size
			err := errors.New("Not all files have the same rows")
			check(err)
		}

		po.rawInput = make([]float64, lenPartyRows)       //8640 lines
		po.flag = make([]int, sectionNum)                 //sections
		po.entropy = make([]float64, sectionNum)          //sections
		po.group = make([]int, sectionSize)               // elements of a section
		po.input = make([][]float64, encryptedSectionNum) //encryption needed

		po.plainInput = make([]float64, 0) //plaintext needed

		tmpStr := ""
		entropySum := 0.0
		for i := range po.rawInput {
			po.rawInput[i] = partyRows[i]
			expSummation[pi] += po.rawInput[i]
			tmpStr += fmt.Sprintf("%.6f", po.rawInput[i])
			if i%sectionSize == sectionSize-1 || i == len(po.rawInput)-1 {
				entropyVal, shannonErr := entropy.Shannon(tmpStr)
				po.entropy[i/sectionSize] = entropyVal
				check(shannonErr)
				tmpStr = ""
				entropySum += po.entropy[i/sectionSize]
				// fmt.Printf("po.entropy[%d] = %v\n", i/sectionSize, po.entropy[i/sectionSize])
			}

		}
		expAverage[pi] = expSummation[pi] / float64(globalPartyRows)
		for i := range po.rawInput {
			temp := po.rawInput[i] - expAverage[pi]
			expDeviation[pi] += temp * temp
		}
		expDeviation[pi] /= float64(globalPartyRows)

		//prepare entropy histogram
		// fmt.Printf("entropy remain[%d] = %.6f\n", -1, entropySum)
		for i := 0; i < encryptedSectionNum; i++ {
			max := -1.0
			index := -1
			for j := 0; j < sectionNum; j++ {
				if po.flag[j] != 1 && po.entropy[j] > max {
					max = po.entropy[j]
					index = j
				}
			}
			po.flag[index] = 1
			entropySum -= max
			// fmt.Printf("entropy remain[%d] = %.6f\n", i, entropySum)
		}

		//prepare data for ciphertext & plaintext
		k := 0
		for i := 0; i < lenPartyRows; i++ {
			if i%sectionSize == 0 && po.flag[i/sectionSize] == 1 {
				po.input[k] = make([]float64, sectionSize) //each input[x] always sized of sectionSize
				k++
			}
			if po.flag[i/sectionSize] == 1 {
				po.input[k-1][i%sectionSize] = po.rawInput[i]
			} else {
				plainSum[pi] += po.rawInput[i]
				po.plainInput = append(po.plainInput, po.rawInput[i]) //plainInput size is not fixed may be the "tail" or sized of sectionSize
			}
		}
	} // each party

	return
}

// outputs the current, total and OS memory being used. As well as the number
// of garage collection cycles completed.
func PrintMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}
