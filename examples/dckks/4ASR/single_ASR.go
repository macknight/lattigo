package main

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
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
	return math.Abs(a-b) <= float64(transitionEqualityThreshold)
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
	filename    string
	sk          *rlwe.SecretKey
	rlkEphemSk  *rlwe.SecretKey
	ckgShare    *drlwe.CKGShare
	rkgShareOne *drlwe.RKGShare
	rkgShareTwo *drlwe.RKGShare
	rtgShare    *drlwe.RTGShare
	pcksShare   *drlwe.PCKSShare

	rawInput       []float64   //all data
	input          [][]float64 //data of encryption
	plainInput     []float64   //data of plain
	encryptedInput []float64   //encrypted data of raw (encrypted value are -0.1)
	flag           []int
	group          []int
	entropy        []float64
	transition     []int
}

type task struct {
	wg          *sync.WaitGroup
	op1         *rlwe.Ciphertext
	op2         *rlwe.Ciphertext
	res         *rlwe.Ciphertext
	elapsedtask time.Duration
}

// mac/Linux
var pathFormat = "../../datasets/%s/households_%d"

// windows
// const pathFormat = "examples\\datasets\\%s\\households_%d"

const MAX_PARTY_ROWS = 20480 //241920
const sectionSize = 2048     // element number within a section
const STRATEGY_GLOBAL_ENTROPY_HIGH_TO_LOW = 1
const STRATEGY_HOUSEHOLD_ENTROPY_HIGH_TO_LOW = 2
const STRATEGY_RANDOM = 3
const DATASET_WATER = 1
const DATASET_ELECTRICITY = 2
const WATER_TRANSITION_EQUALITY_THRESHOLD = 100
const ELECTRICITY_TRANSITION_EQUALITY_THRESHOLD = 2

var confidence_level float64 = 1.0
var attackLoop = 10
var maxHouseholdsNumber = 2
var NGoRoutine int = 1 // Default number of Go routines
var encryptedSectionNum int
var globalPartyRows = -1
var performanceLoops = 1
var currentDataset = 1  //water(1),electricity(2)
var currentStrategy = 1 //GlobalEntropyHightoLow(1), HouseholdEntropyHightoLow(2), Random(3)
var transitionEqualityThreshold int
var sectionNum int
var usedRandomStartPartyPairs = map[int][]int{}

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

	wd, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		return
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

// main start
func process(fileList []string, params ckks.Parameters) {
	P := genparties(params, fileList)
	_, _, _, _, _, entropySum, transitionSum := genInputs(P)
	fmt.Printf("threshold = %.1f, entropy,transition remain = %.3f,%d\n", 0.0, entropySum, transitionSum)

	encryptedSectionNum = sectionNum
	// var plainSum []float64
	var entropyReduction float64
	var transitionReduction int

	for en := 0; en < encryptedSectionNum; en++ {
		fmt.Printf("------------------------------------------encryptedSectionNum = %d\n", en)

		if currentStrategy == STRATEGY_GLOBAL_ENTROPY_HIGH_TO_LOW {
			_, entropyReduction, transitionReduction = markEncryptedSectionsByGlobalEntropyHightoLow(en, P, entropySum, transitionSum)
		} else if currentStrategy == STRATEGY_HOUSEHOLD_ENTROPY_HIGH_TO_LOW {
			_, entropyReduction, transitionReduction = markEncryptedSectionsByHouseholdEntropyHightoLow(en, P, entropySum, transitionSum)
		} else { //STRATEGY_RANDOM
			_, entropyReduction, transitionReduction = markEncryptedSectionsByRandom(en, P, entropySum, transitionSum)
		}
		entropySum -= entropyReduction
		transitionSum -= transitionReduction

		fmt.Printf("<<<beging---encryptedSectionNum = [%d]\n", en)

		memberIdentificationAttack(P) //under current partial encryption
	}

}

func memberIdentificationAttack(P []*party) {
	var attackSuccessNum int
	for a := 0; a < attackLoop; a++ {
		// if a%10 == 0 {
		// 	fmt.Println("loop: ", a)
		// }
		attackSuccessNum += attackParties(P)
	}
	fmt.Printf("<<<<<<<<<<<EncryptedSectionNum = %v, ASR = %.3f\n", encryptedSectionNum, float64(attackSuccessNum)/float64(attackLoop))
}

func attackParties(P []*party) (attackSuccessNum int) {
	// fmt.Println("starting attack>>>>>>>>>>>>>")
	attackSuccessNum = 0
	randomParty := getRandom(maxHouseholdsNumber)

	var valid = false
	var randomStart int

	for !valid {
		randomStart := getRandomStart(randomParty)
		if uniqueRandomStartPartyPair(P, randomParty, randomStart) {
			valid = true
		}
	}

	// randomStart := getRandom(MAX_PARTY_ROWS - sectionSize)
	// fmt.Printf("attacking at Party[%d], position[%d]\n", randomParty, randomStart)

	var leftArr []float64
	var rightArr []float64
	var k int = sectionSize - (randomStart % sectionSize)
	// fmt.Printf(">>pos: %d; ", k)
	// for k := 1; k < sectionSize-1; k++ {
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
		// break
	}

	// }
	// fmt.Println("ending attack#############")
	return
}

func getRandomStart(party int) int {
	var valid bool = false

	var randomStart int

	for !valid {
		randomStart = getRandom(MAX_PARTY_ROWS - sectionSize)
		if !contains(party, randomStart) {
			usedRandomStartPartyPairs[party] = append(usedRandomStartPartyPairs[party], randomStart)
			valid = true
		}
	}
	return randomStart
}

func contains(party int, randomStart int) bool {
	var contains bool = false

	val, exists := usedRandomStartPartyPairs[party]

	if exists {
		for _, v := range val {
			if v == randomStart {
				contains = true
			}
		}
	}

	return contains
}

func uniqueRandomStartPartyPair(P []*party, randomParty int, randomStart int) bool {
	var unique bool = true
	var attacker_data_block = P[randomParty].rawInput[randomStart : randomStart+sectionSize]

	for _, po := range P {
		var household_data = po.rawInput
		for i := 0; i < len(household_data)-sectionSize+1; i++ {
			if i == randomStart {
				continue
			}
			var target = household_data[i : i+sectionSize]
			if reflect.DeepEqual(target, attacker_data_block) {
				unique = false
				break
			}
		}
	}
	return unique
}

func filterParties(P []*party, arr []float64) (resultParties []*party) {
	resultParties = make([]*party, 0)
	var length int = len(arr)

	// var min_length int = int(math.Ceil(float64(length) * confidence_level))
	// var count int = 0

	// for _, po := range P {
	// 	var household_data = po.encryptedInput
	// 	for i := 0; i < len(household_data)-length+1; i++ {
	// 		for j
	// 			var target = household_data[i : i+length]
	// 			if reflect.DeepEqual(target, arr) {
	// 				resultParties = append(resultParties, po)
	// 				break
	// 			}
	// 	}
	// }
	// return

	for _, po := range P {
		var household_data = po.encryptedInput
		for i := 0; i < len(household_data)-length+1; i++ {
			var target = household_data[i : i+length]
			if reflect.DeepEqual(target, arr) {
				resultParties = append(resultParties, po)
				break
			}
		}
	}
	return
}

func markEncryptedSectionsByRandom(en int, P []*party, entropySum float64, transitionSum int) (plainSum []float64, entropyReduction float64, transitionReduction int) {

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

	fmt.Printf("threshold = %.1f, entropy/transition remain = %.3f,%d\n", float64(en+1)/float64(encryptedSectionNum), entropySum-entropyReduction, transitionSum-transitionReduction)

	//for each threshold, prepare plainInput&input
	for pi, po := range P {
		po.input = make([][]float64, 0)
		po.plainInput = make([]float64, 0)
		po.encryptedInput = make([]float64, 0)

		k := 0
		for j := 0; j < globalPartyRows; j++ {
			if j%sectionSize == 0 && j/sectionSize > len(po.flag)-(en+1)-1 {
				po.input = append(po.input, make([]float64, sectionSize))
				k++
			}

			if j/sectionSize > len(po.flag)-(en+1)-1 {
				po.input[k-1][j%sectionSize] = po.rawInput[j]
				po.encryptedInput = append(po.encryptedInput, -0.1)

			} else {
				plainSum[pi] += po.rawInput[j]
				po.plainInput = append(po.plainInput, po.rawInput[j])
				po.encryptedInput = append(po.encryptedInput, po.rawInput[j])
			}
		}
	}
	return
}

func markEncryptedSectionsByGlobalEntropyHightoLow(en int, P []*party, entropySum float64, transitionSum int) (plainSum []float64, entropyReduction float64, transitionReduction int) {

	entropyReduction = 0.0
	transitionReduction = 0
	plainSum = make([]float64, len(P))

	for k := 0; k < len(P); k++ {
		max := -1.0
		sIndex := -1
		pIndex := -1
		for pi, po := range P {
			for si := 0; si < sectionNum; si++ {
				if po.flag[si] != 1 && po.entropy[si] > max {
					max = po.entropy[si]
					sIndex = si
					pIndex = pi
				}
			}
		}
		P[pIndex].flag[sIndex] = 1
		entropyReduction += P[pIndex].entropy[sIndex]
		transitionReduction += P[pIndex].transition[sIndex]
	}

	fmt.Printf("threshold = %.1f, entropy/transition remain = %.3f,%d\n", float64(en+1)/float64(encryptedSectionNum), entropySum-entropyReduction, transitionSum-transitionReduction)

	//for each threshold, prepare plainInput&input
	for pi, po := range P {
		po.input = make([][]float64, 0)
		po.plainInput = make([]float64, 0)
		po.encryptedInput = make([]float64, 0)
		k := 0
		for j := 0; j < globalPartyRows; j++ {
			if j%sectionSize == 0 && po.flag[j/sectionSize] == 1 {
				po.input = append(po.input, make([]float64, sectionSize))
				k++
			}

			if po.flag[j/sectionSize] == 1 {
				po.input[k-1][j%sectionSize] = po.rawInput[j]
				po.encryptedInput = append(po.encryptedInput, -0.1)
			} else {
				plainSum[pi] += po.rawInput[j]
				po.plainInput = append(po.plainInput, po.rawInput[j])
				po.encryptedInput = append(po.encryptedInput, po.rawInput[j])
			}
		}
	}
	return
}

func markEncryptedSectionsByHouseholdEntropyHightoLow(en int, P []*party, entropySum float64, transitionSum int) (plainSum []float64, entropyReduction float64, transitionReduction int) {
	entropyReduction = 0.0
	transitionReduction = 0
	plainSum = make([]float64, len(P))

	for _, po := range P {
		index := 0
		max := -1.0
		for j := 0; j < sectionNum; j++ {
			if po.flag[j] != 1 && po.entropy[j] > max {
				max = po.entropy[j]
				index = j
			}
		}
		po.flag[index] = 1 //po.flag has "sectionNumber" elements
		entropyReduction += po.entropy[index]
		transitionReduction += po.transition[index]
	} // mark one block for each person

	fmt.Printf("threshold = %.1f, entropy/transition remain = %.3f,%d\n", float64(en+1)/float64(encryptedSectionNum), entropySum-entropyReduction, transitionSum-transitionReduction)

	//for each threshold, prepare plainInput&input
	for pi, po := range P {
		po.input = make([][]float64, 0)
		po.plainInput = make([]float64, 0)
		po.encryptedInput = make([]float64, 0)

		k := 0
		for j := 0; j < globalPartyRows; j++ {
			if j%sectionSize == 0 && po.flag[j/sectionSize] == 1 {
				po.input = append(po.input, make([]float64, sectionSize))
				k++
			}

			if po.flag[j/sectionSize] == 1 {
				po.input[k-1][j%sectionSize] = po.rawInput[j]
				po.encryptedInput = append(po.encryptedInput, -0.1)
			} else {
				plainSum[pi] += po.rawInput[j]
				po.plainInput = append(po.plainInput, po.rawInput[j])
				po.encryptedInput = append(po.encryptedInput, po.rawInput[j])
			}
		}
	}
	return
}

// func encryptedSection() [sectionSize]float64 {
// 	arr := [sectionSize]float64{}

// 	// Initialize each element with the same value
// 	for i := 0; i < sectionSize; i++ {
// 		arr[i] = -0.1
// 	}

// 	return arr
// }

func genparties(params ckks.Parameters, fileList []string) []*party {
	P := make([]*party, len(fileList))

	for i, _ := range P {
		po := &party{}
		po.sk = ckks.NewKeyGenerator(params).GenSecretKey()
		po.filename = fileList[i]
		P[i] = po
	}

	return P
}

// file reading
func ReadCSV(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	dArray := strings.Split(string(data), "\n")
	return dArray[:len(dArray)-1]
}

// trim csv
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

// generate inputs of parties
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
