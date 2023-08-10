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

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) <= float64(transitionEqualityThreshold)
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
var tmpTimeSummation time.Duration
var tmpTimeDeviation time.Duration

var standardErrorSummation float64
var standardErrorDeviation float64

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
	entropy    []float64 //entropy for block
	transition []float64
}

type task struct {
	wg          *sync.WaitGroup
	op1         *rlwe.Ciphertext
	op2         *rlwe.Ciphertext
	res         *rlwe.Ciphertext
	elapsedtask time.Duration
}

const STRATEGY_GLOBAL = 1
const STRATEGY_HOUSEHOLD = 2
const STRATEGY_RANDOM = 3

const DATASET_WATER = 1
const DATASET_ELECTRICITY = 2

const WATER_TRANSITION_EQUALITY_THRESHOLD = 100
const ELECTRICITY_TRANSITION_EQUALITY_THRESHOLD = 2

var attackLoop = 1
var maxHouseholdsNumber = 80
var NGoRoutine int = 1 // Default number of Go routines
var encryptedSectionNum int
var globalPartyRows = -1

const PERFORMANCE_LOOPS = 2000
const MAX_PARTY_ROWS = 10240 // total reocrds per household
const sectionSize = 1024     //block size, 2048 for summation correctness, 8192 for variance correctness

var currentDataset = 1  //water(1),electricity(2)
var currentStrategy = 1 //Global(1), Household(2), Random(3)
var currentTarget = 2   //entropy(1),transition(2)

var transitionEqualityThreshold int
var sectionNum int

func main() {
	var args []int

	for _, arg := range os.Args[1:] {
		num, err := strconv.Atoi(arg)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		args = append(args, num)
	}

	if len(args) > 0 {
		currentStrategy = args[0]
		currentDataset = args[1]
		currentTarget = args[2]
	}

	fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	if currentStrategy == STRATEGY_GLOBAL {
		fmt.Println("Strategy: Global Entropy High To Low")
	} else if currentStrategy == STRATEGY_HOUSEHOLD {
		fmt.Println("Strategy: Household Entropy High To Low")
	} else {
		fmt.Println("Strategy: Random")
	}
	if currentDataset == DATASET_WATER {
		fmt.Println("Dataset: Water")
	} else {
		fmt.Println("Dataset: Electricity")
	}
	if currentTarget == 1 {
		fmt.Println("Target: Entropy based")
	} else {
		fmt.Println("Target: Transition based")
	}
	// fmt.Println("SE threshold ", 0.01)
	fmt.Println("Performance Loop: ", PERFORMANCE_LOOPS)
	fmt.Println("Number of Households: ", maxHouseholdsNumber)

	fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

	rand.Seed(time.Now().UnixNano())

	start := time.Now()

	fileList := []string{}
	var err error
	paramsDef := ckks.PN10QP27CI // PN10QP27CI, PN11QP54CI for summation correctness, PN13QP218CI for variance correctness
	params, err := ckks.NewParametersFromLiteral(paramsDef)
	check(err)
	if err != nil {
		fmt.Println("Error:", err)
	}

	// Get the current working directory
	wd, err := os.Getwd()

	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		return
	}

	var pathFormat string
	if strings.Contains(wd, "examples") {
		pathFormat = filepath.Join("..", "..", "..", "examples", "datasets", "%s", "households_%d")
	} else {
		pathFormat = filepath.Join("examples", "datasets", "%s", "households_%d")
	}
	var path string
	if currentDataset == DATASET_WATER {
		path = fmt.Sprintf(pathFormat, "water", MAX_PARTY_ROWS)
		transitionEqualityThreshold = WATER_TRANSITION_EQUALITY_THRESHOLD
	} else { //electricity
		path = fmt.Sprintf(pathFormat, "electricity", MAX_PARTY_ROWS)
		transitionEqualityThreshold = ELECTRICITY_TRANSITION_EQUALITY_THRESHOLD
	}

	folder := filepath.Join(wd, path)
	err = filepath.Walk(folder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
			return err
		}
		if !info.IsDir() {
			// fileName := filepath.Base(path)
			fileList = append(fileList, path)
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
	expSummation, expAverage, expDeviation, min, max, entropySum, transitionSum := genInputs(P)
	histogram := genHistogram(P, min, max)
	fmt.Printf(">>>>>>>Entropy Histograme:\n")
	for i := 0; i < len(histogram); i++ {
		fmt.Printf("%.3f,%d\n", float64(i)/20+0.025, histogram[i])
	}

	//mark blocks needing to be encrypted
	fmt.Printf("threshold = %.1f, entropy/transition remain = %.3f,%.3f\n", 0.0, entropySum, transitionSum/1000.0)

	encryptedSectionNum = sectionNum
	var plainSum []float64
	var entropyReduction float64
	var transitionReduction float64
	for en := 0; en < encryptedSectionNum; en++ {
		// fmt.Printf("------------------------------------------encryptedSectionNum = %d\n", en)

		if currentStrategy == STRATEGY_GLOBAL {
			plainSum, entropyReduction, transitionReduction = markEncryptedSectionsByGlobal(en, P, entropySum, transitionSum)
		} else if currentStrategy == STRATEGY_HOUSEHOLD {
			plainSum, entropyReduction, transitionReduction = markEncryptedSectionsByHousehold(en, P, entropySum, transitionSum)
		} else { //STRATEGY_RANDOM
			plainSum, entropyReduction, transitionReduction = markEncryptedSectionsByRandom(en, P, entropySum, transitionSum)
		}
		entropySum -= entropyReduction
		transitionSum -= transitionReduction

		// fmt.Printf("<<<beging---encryptedSectionNum = [%d]\n", en)

		// memberIdentificationAttack(P) //under current partial encryption

		//HE performance by loops

		// var summationSample = []float64{}
		// var DeviationSample = []float64{}
		performanceLoop := 1
		elapsedSummation = 0.0
		elapsedDeviation = 0.0
		for ; performanceLoop <= PERFORMANCE_LOOPS; performanceLoop++ {
			// elapsedSummation = 0.0
			// elapsedDeviation = 0.0
			// fmt.Printf("<<<performanceLoop = [%d], encryptedSectionNum = [%d]\n", performanceLoop, en)
			doHomomorphicOperations(params, P, expSummation, expAverage, expDeviation, plainSum)
			// summationSample = append(summationSample, float64(elapsedSummation))
			// DeviationSample = append(DeviationSample, float64(elapsedDeviation))
			// tmpTimeSummation += elapsedSummation
			// tmpTimeDeviation += elapsedDeviation
			// if PERFORMANCE_LOOPS >= 100 {
			// 	standardErrorSummation = calculateStandardError(summationSample)
			// 	standardErrorDeviation = calculateStandardError(summationSample)
			// 	if standardErrorSummation <= 0.01 && standardErrorDeviation <= 0.01 {
			// 		break
			// 	}
			// }
		}
		// performance prints
		// elapsedSummation = tmpTimeSummation
		// elapsedDeviation = tmpTimeDeviation
		showHomomorphicMeasure(performanceLoop, params)
	}
}

func memberIdentificationAttack(P []*party) {
	var attackSuccessNum int
	for a := 0; a < attackLoop; a++ {
		attackSuccessNum += attackParties(P)
	}
	fmt.Printf("<<<<<<<<<<<EncryptedSectionNum = %v, ASR = %.3f\n", encryptedSectionNum, float64(attackSuccessNum)/float64(attackLoop))
}

func attackParties(P []*party) (attackSuccessNum int) {
	// fmt.Println("starting attack>>>>>>>>>>>>>")
	attackSuccessNum = 0
	randomParty := getRandom(maxHouseholdsNumber)
	randomStart := getRandom(MAX_PARTY_ROWS - sectionSize)
	// fmt.Printf("attackering at Party[%d], position[%d]\n", randomParty, randomStart)

	var leftArr []float64
	var rightArr []float64
	for k := 1; k < sectionSize-1; k++ {
		leftArr = make([]float64, 0)
		rightArr = make([]float64, 0)
		// fmt.Printf("<<pos: %d; ", k)
		var tmpParties []*party
		//search with left part
		for i := 0; i < k; i++ {
			leftArr = append(leftArr, P[randomParty].rawInput[i+randomStart])
		}
		tmpParties = filterParties(P, leftArr)

		if len(tmpParties) == 0 {
			tmpParties = P
		}

		//search with right part
		for j := k; j < sectionSize; j++ {
			rightArr = append(rightArr, P[randomParty].rawInput[j+randomStart])
		}
		tmpParties = filterParties(tmpParties, rightArr)
		if len(tmpParties) == 1 {
			attackSuccessNum = 1
			// fmt.Printf("!!!!!!!!Success with party file[%s]\n", filepath.Base(tmpParties[0].filename))
			break
		}
	}
	// fmt.Println("ending attack#############")
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
				} else if k == len(arr) {
					matched = true
				}
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

func markEncryptedSectionsByRandom(en int, P []*party, entropySum, transitionSum float64) (plainSum []float64, entropyReduction float64, transitionReduction float64) {

	entropyReduction = 0.0
	transitionReduction = 0
	plainSum = make([]float64, len(P))

	for _, po := range P {
		if en == 0 {
			for i := 0; i < len(po.flag); i++ {
				po.flag[i] = i
			}
		}
		r := getRandom(encryptedSectionNum - en)
		index := po.flag[r]
		entropyReduction += po.entropy[index]
		transitionReduction += po.transition[index]
		po.flag[r] = po.flag[encryptedSectionNum-1-en]
		po.flag[encryptedSectionNum-1-en] = index
	} // mark randomly

	// fmt.Println("----------------------------------------------->")
	fmt.Printf("threshold = %.1f, entropy/transition remain = %.3f,%.3f\n", float64(en+1)/float64(encryptedSectionNum), entropySum-entropyReduction, (transitionSum-transitionReduction)/1000.0)

	//for each threshold, prepare plainInput&input
	for pi, po := range P {
		po.input = make([][]float64, 0)
		po.plainInput = make([]float64, 0)
		k := 0
		for j := 0; j < globalPartyRows; j++ {
			if j%sectionSize == 0 && j/sectionSize > len(po.flag)-(en+1)-1 {
				po.input = append(po.input, make([]float64, sectionSize))
				k++
			}

			if j/sectionSize > len(po.flag)-(en+1)-1 {
				po.input[k-1][j%sectionSize] = po.rawInput[j]
			} else {
				plainSum[pi] += po.rawInput[j]
				po.plainInput = append(po.plainInput, po.rawInput[j])
			}
		}
	}
	return
}

func markEncryptedSectionsByGlobal(en int, P []*party, entropySum, transitionSum float64) (plainSum []float64, entropyReduction float64, transitionReduction float64) {

	entropyReduction = 0.0
	transitionReduction = 0
	plainSum = make([]float64, len(P))
	var targetArr []float64

	for k := 0; k < len(P); k++ {
		max := -1.0
		sIndex := -1
		pIndex := -1
		for pi, po := range P {
			if currentTarget == 1 {
				targetArr = po.entropy
			} else {
				targetArr = po.transition
			}
			for si := 0; si < sectionNum; si++ {
				if po.flag[si] != 1 && targetArr[si] > max {
					max = targetArr[si]
					sIndex = si
					pIndex = pi
				}
			}
		}
		P[pIndex].flag[sIndex] = 1
		entropyReduction += P[pIndex].entropy[sIndex]
		transitionReduction += P[pIndex].transition[sIndex]
	}
	// fmt.Println("----------------------------------------------->")
	fmt.Printf("threshold = %.1f, entropy/transition remain = %.3f,%.3f\n", float64(en+1)/float64(encryptedSectionNum), entropySum-entropyReduction, (transitionSum-transitionReduction)/1000.0)

	//for each threshold, prepare plainInput&input
	for pi, po := range P {
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

func markEncryptedSectionsByHousehold(en int, P []*party, entropySum, transitionSum float64) (plainSum []float64, entropyReduction float64, transitionReduction float64) {
	entropyReduction = 0.0
	transitionReduction = 0
	plainSum = make([]float64, len(P))
	var targetArr []float64

	for _, po := range P {
		index := 0
		max := -1.0
		if currentTarget == 1 {
			targetArr = po.entropy
		} else {
			targetArr = po.transition
		}
		for j := 0; j < sectionNum; j++ {
			if po.flag[j] != 1 && targetArr[j] > max {
				max = targetArr[j]
				index = j
			}
		}
		po.flag[index] = 1 //po.flag has "sectionNumber" elements
		entropyReduction += po.entropy[index]
		transitionReduction += po.transition[index]
	} // mark one block for each person
	// fmt.Println("----------------------------------------------->")
	fmt.Printf("threshold = %.1f, entropy/transition remain = %.3f,%.3f\n", float64(en+1)/float64(encryptedSectionNum), entropySum-entropyReduction, (transitionSum-transitionReduction)/1000.0)

	//for each threshold, prepare plainInput&input
	for pi, po := range P {
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

	// fmt.Println("1~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	fmt.Printf("standardError: %.3f, %.3f\n", standardErrorSummation, standardErrorDeviation)
	fmt.Printf("***** Evaluating Summation/Deviation time for %d households in thirdparty analyst's side: %s,%s\n", maxHouseholdsNumber, time.Duration(elapsedSummation.Nanoseconds()/int64(loop)), time.Duration(elapsedDeviation.Nanoseconds()/int64(loop)))

	// fmt.Println("2~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

	// //public key & relinearization key & rotation key
	// fmt.Printf("*****Amortized SKG Time: %s\n", time.Duration(elapsedSKGParty.Nanoseconds()/int64(loop)))
	// fmt.Printf("*****Amortized PKG Time: %s\n", time.Duration(elapsedPKGParty.Nanoseconds()/int64(loop)))
	// fmt.Printf("*****Amortized RKG Time: %s\n", time.Duration(elapsedRKGParty.Nanoseconds()/int64(loop)))
	// fmt.Printf("*****Amortized RTG Time: %s\n", time.Duration(elapsedRTGParty.Nanoseconds()/int64(loop)))

	// //single operation, independent of households' size
	// fmt.Printf("*****Amortized Encrypt Time: %s\n", time.Duration(elapsedEncryptParty.Nanoseconds()/int64(loop)))
	// fmt.Printf("*****Amortized Decrypt Time: %s\n", time.Duration(elapsedDecParty.Nanoseconds()/int64(loop)))
	// fmt.Printf("*****Amortized Ciphertext Addition Time: %s\n", time.Duration(elapsedAddition.Nanoseconds()/int64(loop)))
	// fmt.Printf("*****Amortized Ciphertext Multiplication Time: %s\n", time.Duration(elapsedMultiplication.Nanoseconds()/int64(loop)))
	// fmt.Printf("*****Amortized Ciphertext Rotation Time: %s\n", time.Duration(elapsedRotation.Nanoseconds()/int64(loop*len(params.GaloisElementsForRowInnerSum()))))

	// fmt.Printf("*****Amortized Analyst Time: %s\n", time.Duration(elapsedAnalystSummation.Nanoseconds()/int64(loop)))
	// fmt.Printf("*****Amortized Analyst Time: %s\n", time.Duration(elapsedAnalystVariance.Nanoseconds()/int64(loop)))

	// PrintMemUsage()
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

	//generate ciphertexts====================================================
	encInputsSummation, encInputsNegative := encPhase(params, P, tpk, encoder)

	// summation calculation====================================================
	encSummationOuts := make([]*rlwe.Ciphertext, len(P))
	anaTime1 := time.Now()
	var tmpCiphertext *rlwe.Ciphertext
	for i, _ := range encInputsSummation {
		for j, _ := range encInputsSummation[i] {
			if j == 0 {
				tmpCiphertext = encInputsSummation[i][j]
			} else {
				elapsedSummation += runTimed(func() {
					evaluator.Add(tmpCiphertext, encInputsSummation[i][j], tmpCiphertext)
				})
			}

			if j == len(encInputsSummation[i])-1 {
				elapsedSummation += runTimed(func() {
					elapsedRotation += runTimedParty(func() {
						evaluator.InnerSum(tmpCiphertext, 1, params.Slots(), tmpCiphertext)
					}, len(P))
				})
				encSummationOuts[i] = tmpCiphertext
			}
		} //j
	} //i
	elapsedAnalystSummation += time.Since(anaTime1)

	// deviation calculation====================================================
	encDeviationOuts := make([]*rlwe.Ciphertext, len(P))
	anaTime2 := time.Now()
	var avergeCiphertext *rlwe.Ciphertext
	for i, _ := range encInputsNegative {
		for j, _ := range encInputsNegative[i] {
			if j == 0 {
				avergeCiphertext = encSummationOuts[i].CopyNew()
				avergeCiphertext.Scale = avergeCiphertext.Mul(rlwe.NewScale(globalPartyRows))
			}
			elapsedDeviation += runTimed(func() {
				elapsedAddition += runTimedParty(func() {
					evaluator.Add(encInputsNegative[i][j], avergeCiphertext, encInputsNegative[i][j])
				}, len(P))

				elapsedMultiplication += runTimedParty(func() {
					evaluator.MulRelin(encInputsNegative[i][j], encInputsNegative[i][j], encInputsNegative[i][j])
				}, len(P))

				if j == 0 {
					tmpCiphertext = encInputsNegative[i][j]
				} else {
					elapsedRotation += runTimedParty(func() {
						evaluator.Add(tmpCiphertext, encInputsNegative[i][j], tmpCiphertext)
					}, len(P))
				}

				if j == len(encInputsNegative[i])-1 {
					elapsedRotation += runTimedParty(func() {
						evaluator.InnerSum(tmpCiphertext, 1, params.Slots(), tmpCiphertext)
					}, len(P))
					tmpCiphertext.Scale = tmpCiphertext.Mul(rlwe.NewScale(globalPartyRows))
					encDeviationOuts[i] = tmpCiphertext
				}
			})
		} //j
	} //i
	elapsedAnalystVariance += time.Since(anaTime2)

	// Decrypt & Print====================================================
	// fmt.Println("> Decrypt & Result:>>>>>>>>>>>>>")

	// print summation
	ptresSummation := ckks.NewPlaintext(params, params.MaxLevel())
	for i, _ := range encSummationOuts {
		if encSummationOuts[i] != nil {
			decryptor.Decrypt(encSummationOuts[i], ptresSummation) //ciphertext->plaintext
			encoder.Decode(ptresSummation, params.LogSlots())      //resSummation :=
			// fmt.Printf("CKKS Summation of Party[%d]=%.6f\t", i, real(resSummation[0])+plainSum[i])
			// fmt.Printf(" <===> Expected Summation of Party[%d]=%.6f\t", i, expSummation[i])
			// fmt.Println()
		}
	}

	// print deviation
	ptresDeviation := ckks.NewPlaintext(params, params.MaxLevel())
	for i, _ := range encDeviationOuts {
		if encDeviationOuts[i] != nil {
			elapsedDecParty += runTimedParty(func() {
				// decryptor.Decrypt(encAverageOuts[i], ptres)            //ciphertext->plaintext
				decryptor.Decrypt(encDeviationOuts[i], ptresDeviation) //ciphertext->plaintext
			}, len(P))

			// res := encoder.Decode(ptres, params.LogSlots())
			encoder.Decode(ptresDeviation, params.LogSlots()) //resDeviation :=

			// calculatedAverage := real(res[0])
			// calculatedAverage := expAverage[i]

			// fmt.Printf("CKKS Average of Party[%d]=%.6f\t", i, calculatedAverage)
			// fmt.Printf(" <===> Expected Average of Party[%d]=%.6f\t", i, expAverage[i])
			// fmt.Println()

			//extra value for deviation
			// delta := calculatedAverage * calculatedAverage * float64(len(resDeviation)-globalPartyRows) / float64(globalPartyRows)

			// fmt.Printf("CKKS Deviation of Party[%d]=%.6f\t", i, real(resDeviation[0])) //real(resDeviation[0])-delta
			// fmt.Printf(" <===> Expected Deviation of Party[%d]=%.6f\t", i, expDeviation[i])
			// fmt.Println()
		}
	}
	// fmt.Printf("\tDecrypt Time: done %s\n", elapsedDecParty)
	// fmt.Println()

	//print result
	// visibleNum := 4
	// fmt.Println("> Parties:")
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

func encPhase(params ckks.Parameters, P []*party, pk *rlwe.PublicKey, encoder ckks.Encoder) (encInputsSummation, encInputsNegative [][]*rlwe.Ciphertext) {

	encInputsSummation = make([][]*rlwe.Ciphertext, len(P))
	encInputsNegative = make([][]*rlwe.Ciphertext, len(P))

	// Each party encrypts its input vector
	// fmt.Println("> Encrypt Phase<<<<<<<<<<<<<<<<<<")
	encryptor := ckks.NewEncryptor(params, pk)
	pt := ckks.NewPlaintext(params, params.MaxLevel())

	elapsedEncryptParty += runTimedParty(func() {
		for pi, po := range P {
			for j, _ := range po.input {
				if j == 0 {
					encInputsSummation[pi] = make([]*rlwe.Ciphertext, 0)
					encInputsNegative[pi] = make([]*rlwe.Ciphertext, 0)
				}
				//Encrypt
				encoder.Encode(po.input[j], pt, params.LogSlots())
				tmpCiphertext := ckks.NewCiphertext(params, 1, params.MaxLevel())
				encryptor.Encrypt(pt, tmpCiphertext)
				encInputsSummation[pi] = append(encInputsSummation[pi], tmpCiphertext)

				//turn po.input to negative
				for k, _ := range po.input[j] {
					po.input[j][k] *= -1
				}
				//Encrypt
				encoder.Encode(po.input[j], pt, params.LogSlots())
				tmpCiphertext = ckks.NewCiphertext(params, 1, params.MaxLevel())
				encryptor.Encrypt(pt, tmpCiphertext)
				encInputsNegative[pi] = append(encInputsNegative[pi], tmpCiphertext)
				////turn po.input to positive
				for k, _ := range po.input[j] {
					po.input[j][k] *= -1
				}
			}
		}
	}, 2*len(P)) //2 encryption in function

	// fmt.Printf("\tdone  %s\n", elapsedEncryptParty)

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
	csv := ReadCSV(filename)

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

func genHistogram(P []*party, min, max float64) (histogram []int) {
	histogram = make([]int, HISTOGRAM_CATEGORY_SIZE)
	denominator := max - min
	for _, po := range P {
		var targetArr []float64
		if currentTarget == 1 {
			targetArr = po.entropy
		} else {
			targetArr = po.transition
		}
		for _, ele := range targetArr {
			percentage := (ele - min) / denominator
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
func genInputs(P []*party) (expSummation, expAverage, expDeviation []float64, min, max, entropySum, transitionSum float64) {

	sectionNum = 0
	min = math.MaxFloat64
	max = float64(-1)
	frequencyMap := map[float64]int{}
	entropyMap := map[float64]float64{}

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

		po.rawInput = make([]float64, globalPartyRows)

		po.flag = make([]int, sectionNum)
		po.entropy = make([]float64, sectionNum)
		po.transition = make([]float64, sectionNum)
		po.group = make([]int, sectionSize)

		for i := range po.rawInput {
			po.rawInput[i] = math.Round(partyRows[i]*1000) / 1000 // hold 3 decimal places

			val, exists := frequencyMap[po.rawInput[i]]
			if exists {
				val++
			} else {
				val = 1
			}
			frequencyMap[po.rawInput[i]] = val

			expSummation[pi] += po.rawInput[i]
		} //each line of one person

		expAverage[pi] = expSummation[pi] / float64(globalPartyRows)
		for i := range po.rawInput {
			temp := po.rawInput[i] - expAverage[pi]
			expDeviation[pi] += temp * temp
		}
		expDeviation[pi] /= float64(globalPartyRows)
	} // each person

	totalRecords := maxHouseholdsNumber * MAX_PARTY_ROWS
	for k, _ := range frequencyMap {
		possibility := float64(frequencyMap[k]) / float64(totalRecords)
		entropyMap[k] = -possibility * math.Log2(possibility)
	}

	for _, po := range P {
		for i := range po.rawInput {
			singleRecordEntropy := entropyMap[po.rawInput[i]] / float64(frequencyMap[po.rawInput[i]])
			po.entropy[i/sectionSize] += singleRecordEntropy
			entropySum += singleRecordEntropy
			if i > 0 && !almostEqual(po.rawInput[i], po.rawInput[i-1]) {
				po.transition[i/sectionSize] += 1
				transitionSum++
			}
		}
	}

	//max,min based on currentTarget
	for _, po := range P {
		var targetArr []float64
		if currentTarget == 1 {
			targetArr = po.entropy
		} else {
			targetArr = po.transition
		}

		for sIndex := range targetArr {
			if targetArr[sIndex] > max {
				max = targetArr[sIndex]
			}
			if targetArr[sIndex] < min {
				min = targetArr[sIndex]
			}
		}
	}

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

func calculateStandardError(numbers []float64) float64 {
	standardDeviation := calculateStandardDeviation(numbers)
	standard_error := standardDeviation / math.Sqrt(float64(len(numbers)))
	return standard_error
}

func calculateStandardDeviation(numbers []float64) float64 {
	var sum float64
	for _, num := range numbers {
		sum += num
	}
	mean := sum / float64(len(numbers))

	var squaredDifferences float64
	for _, num := range numbers {
		difference := num - mean
		squaredDifferences += difference * difference
	}

	variance := squaredDifferences / (float64(len(numbers)) - 1)

	standardDeviation := math.Sqrt(variance)

	return standardDeviation
}
