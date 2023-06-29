package main

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
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
	return math.Abs(a-b) <= transitionEqualityThreshold
}

func check(err error) {
	if err != nil {
		panic(err)
	}
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
	filename    string
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
	transition []int
}

type task struct {
	wg          *sync.WaitGroup
	op1         *rlwe.Ciphertext
	op2         *rlwe.Ciphertext
	res         *rlwe.Ciphertext
	elapsedtask time.Duration
}

const pathFormat = "C:\\Users\\23304161\\source\\Datasets\\water\\swm_trialA_1K\\households_%d"
const fileFormat = "C:\\Users\\23304161\\source\\Datasets\\water\\swm_trialA_1K\\households_%d\\%s"
const MAX_PARTY_ROWS = 20480 //241920
const transitionEqualityThreshold = 100
const sectionSize = 2048 // element number within a section

var maxHouseholdsNumber = 80
var NGoRoutine int = 1 // Default number of Go routines
var encryptedSectionNum int
var sectionNum int
var globalPartyRows = -1
var performanceLoops = 1

func main() {
	rand.Seed(time.Now().UnixNano())

	start := time.Now()

	fileList := []string{}
	var err error
	paramsDef := ckks.PN11QP54CI // block size = 4096
	params, err := ckks.NewParametersFromLiteral(paramsDef)
	check(err)
	if err != nil {
		fmt.Println("Error:", err)
	}

	folder := fmt.Sprintf(pathFormat, MAX_PARTY_ROWS)
	err = filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
			return err
		}
		if !info.IsDir() {
			fileName := filepath.Base(path)
			fileList = append(fileList, fileName)
			// fmt.Printf("filename: %s\n", fileName)
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
	}
	process(fileList[:maxHouseholdsNumber], params)

	fmt.Printf("Main() Done in %s \n", time.Since(start))
}

//main start
func process(fileList []string, params ckks.Parameters) {

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := genparties(params, fileList)

	//getInputs read the data file
	// Inputs & expected result, cleartext result
	expSummation, expAverage, expDeviation, minEntropy, maxEntropy, entropySum, transitionSum := genInputs(P)
	_ = expSummation
	_ = expAverage
	_ = expDeviation
	histogram := genHistogram(P, minEntropy, maxEntropy)
	fmt.Printf(">>>>>>>Entropy Histograme:\n")
	for i := 0; i < len(histogram); i++ {
		fmt.Printf("[%d]: %d\n", i, histogram[i])
	}

	//mark blocks needing to be encrypted
	fmt.Printf("transitionEqualityThreshold: %d\n", transitionEqualityThreshold)
	fmt.Printf("entropy remain[initial] = %.3f; transition remain[initial] = %d\n", entropySum, transitionSum)

	encryptedSectionNum = sectionNum

	for en := 0; en < encryptedSectionNum; en++ {
		plainSum, entropyReduction, transitionReduction := markEncryptedSections(en, P, entropySum, transitionSum)
		entropySum -= entropyReduction
		transitionSum -= transitionReduction

		_ = plainSum
		//performance by loops
		for performanceLoop := 0; performanceLoop < performanceLoops; performanceLoop++ {
			// fmt.Printf("<<<encryptedSectionNum = %d, performanceLoop = %d\n", en, performanceLoop)
			// doHomomorphicOperations(params, P, expSummation, expAverage, expDeviation, plainSum)
		}
		//performance prints
		// fmt.Printf("------------------------------------------encryptedSectionNum = %d\n", en)
		// showHomomorphicMeasure(performanceLoops, params)
	}
}

//main end

func markEncryptedSections(en int, P []*party, entropySum float64, transitionSum int) (plainSum []float64, entropyReduction float64, transitionReduction int) {
	entropyReduction = 0.0
	transitionReduction = 0

	for _, po := range P {
		index := 0
		max := -1.0
		for j := 0; j < sectionNum; j++ {
			if po.flag[j] != 1 && po.entropy[j] > max {
				max = po.entropy[j]
				index = j
			}
		}
		po.flag[index] = 1
		entropyReduction += po.entropy[index]
		transitionReduction += po.transition[index]
	} //each person

	fmt.Printf("entropy remain[%d] = %.3f (diff: %.3f), transition remain[%d] = %d (diff: %d)\n", en, entropySum-entropyReduction, entropyReduction, en, transitionSum-transitionReduction, transitionReduction)

	//for each threshold, prepare plainInput&input
	for pi, po := range P {
		plainSum = make([]float64, len(P))
		po.input = make([][]float64, 0)
		po.plainInput = make([]float64, 0)
		k := 0
		for j := 0; j < globalPartyRows; j++ {
			if j%sectionSize == 0 && po.flag[j/sectionSize] == 1 {
				po.input = append(po.input, make([]float64, sectionSize))
				k++
			}

			if po.flag[j/sectionSize] == 1 {
				po.input[k-1][j%sectionSize] = po.rawInput[j]
			} else {
				plainSum[pi] += po.rawInput[j]
				po.plainInput = append(po.plainInput, po.rawInput[j])
			}
		}
	}
	return
}

func showHomomorphicMeasure(loop int, params ckks.Parameters) {

	fmt.Println("1~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	fmt.Printf("***** Evaluating Summation time for %d households in thirdparty analyst's side: %s\n", maxHouseholdsNumber, time.Duration(elapsedSummation.Nanoseconds()/int64(loop)))
	fmt.Printf("***** Evaluating Deviation time for %d households in thirdparty analyst's side: %s\n", maxHouseholdsNumber, time.Duration(elapsedDeviation.Nanoseconds()/int64(loop)))

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

	PrintMemUsage()
}

func doHomomorphicOperations(params ckks.Parameters, P []*party, expSummation, expAverage, expDeviation, plainSum []float64) {
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

	//generate ciphertexts
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
	fmt.Println("> Decrypt & Result:>>>>>>>>>>>>>")

	// print summation
	ptresSummation := ckks.NewPlaintext(params, params.MaxLevel())
	for i, _ := range encSummationOuts {
		decryptor.Decrypt(encSummationOuts[i], ptresSummation) //ciphertext->plaintext
		resSummation := encoder.Decode(ptresSummation, params.LogSlots())
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

func encPhase(params ckks.Parameters, P []*party, pk *rlwe.PublicKey, encoder ckks.Encoder) (encInputsNegative, encInputsSummation []*rlwe.Ciphertext) {

	encInputsNegative = make([]*rlwe.Ciphertext, len(P)*encryptedSectionNum)
	encInputsSummation = make([]*rlwe.Ciphertext, len(P)*encryptedSectionNum)

	for i := range encInputsSummation {
		encInputsNegative[i] = ckks.NewCiphertext(params, 1, params.MaxLevel())
		encInputsSummation[i] = ckks.NewCiphertext(params, 1, params.MaxLevel())
	}

	// Each party encrypts its input vector
	fmt.Println("> Encrypt Phase<<<<<<<<<<<<<<<<<<")
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

	fmt.Printf("\tdone  %s\n", elapsedEncryptParty)

	return
}

//generate parties
func genparties(params ckks.Parameters, fileList []string) []*party {

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := make([]*party, len(fileList))

	for i, _ := range P {
		po := &party{}
		po.sk = ckks.NewKeyGenerator(params).GenSecretKey()
		po.filename = fileList[i]
		P[i] = po
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
	// dArray2 := dArray[1 : len(dArray)-1]
	// fmt.Println("data CSV size:", len(dArray)) //[0]..[241919]
	return dArray[:len(dArray)-1]
}

//trim csv
func resizeCSV(filename string) []float64 {

	filepath := fmt.Sprintf(fileFormat, MAX_PARTY_ROWS, filename)
	csv := ReadCSV(filepath)

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

func getRandom(numberRange int) (randNumber int) {
	randNumber = rand.Intn(numberRange) //[0, numberRange-1]
	return
}

const HISTOGRAM_CATEGORY_SIZE = 20

func genHistogram(P []*party, minEntropy, maxEntropy float64) (histogram []int) {
	histogram = make([]int, HISTOGRAM_CATEGORY_SIZE)
	denominator := maxEntropy - minEntropy
	for _, po := range P {
		for _, entropy := range po.entropy {
			percentage := (entropy - minEntropy) / denominator
			index := int(math.Floor(HISTOGRAM_CATEGORY_SIZE * percentage))
			if index == HISTOGRAM_CATEGORY_SIZE {
				index--
			}
			histogram[index]++
		}
	}
	return
}

//generate inputs of parties
func genInputs(P []*party) (expSummation, expAverage, expDeviation []float64, minEntropy, maxEntropy, entropySum float64, transitionSum int) {

	sectionNum = 0
	minEntropy = math.MaxFloat64
	maxEntropy = float64(-1)

	entropySum = 0.0
	transitionSum = 0
	for pi, po := range P {
		partyRows := resizeCSV(po.filename)
		lenPartyRows := len(partyRows)
		if lenPartyRows > MAX_PARTY_ROWS {
			lenPartyRows = MAX_PARTY_ROWS
		}

		if globalPartyRows == -1 {
			sectionNum = lenPartyRows / sectionSize
			if lenPartyRows%sectionSize != 0 {
				sectionNum++
			}
			globalPartyRows = lenPartyRows
			expSummation = make([]float64, len(P))
			expAverage = make([]float64, len(P))
			expDeviation = make([]float64, len(P))
		} else if globalPartyRows != lenPartyRows {
			//make sure pi.input[] has the same size
			err := errors.New("Not all files have the same rows")
			check(err)
		}

		po.rawInput = make([]float64, lenPartyRows)
		po.flag = make([]int, sectionNum)
		po.entropy = make([]float64, sectionNum)
		po.transition = make([]int, sectionNum)
		po.group = make([]int, sectionSize)

		tmpStr := ""
		transitionInsideSection := 0
		for i := range po.rawInput {
			po.rawInput[i] = partyRows[i]
			expSummation[pi] += po.rawInput[i]
			if i > 0 && !almostEqual(po.rawInput[i], po.rawInput[i-1]) {
				transitionInsideSection++
			}
			//count transitions of each section
			tmpStr += fmt.Sprintf("%f", po.rawInput[i])
			if i%sectionSize == sectionSize-1 || i == len(po.rawInput)-1 {
				//transition
				po.transition[i/sectionSize] = transitionInsideSection
				transitionSum += transitionInsideSection
				transitionInsideSection = 0
				//entropy
				entropyVal, shannonErr := entropy.Shannon(tmpStr)
				check(shannonErr)
				if entropyVal > maxEntropy {
					maxEntropy = entropyVal
				}
				if entropyVal < minEntropy {
					minEntropy = entropyVal
				}
				po.entropy[i/sectionSize] = entropyVal
				tmpStr = ""
				entropySum += entropyVal
				// fmt.Printf("po.entropy[%d] = %.6f\n", i/sectionSize, po.entropy[i/sectionSize])
			}
		} //each line

		expAverage[pi] = expSummation[pi] / float64(globalPartyRows)
		for i := range po.rawInput {
			temp := po.rawInput[i] - expAverage[pi]
			expDeviation[pi] += temp * temp
		}
		expDeviation[pi] /= float64(globalPartyRows)
	} // each person

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
