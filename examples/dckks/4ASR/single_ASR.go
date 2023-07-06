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
// var pathFormat = "../../datasets/%s/households_%d"

// windows
const pathFormat = "examples\\datasets\\%s\\households_%d"

const MAX_PARTY_ROWS = 20480 //241920
const sectionSize = 2048     // element number within a section
const STRATEGY_GLOBAL_ENTROPY_HIGH_TO_LOW = 1
const STRATEGY_HOUSEHOLD_ENTROPY_HIGH_TO_LOW = 2
const STRATEGY_RANDOM = 3
const DATASET_WATER = 1
const DATASET_ELECTRICITY = 2
const WATER_TRANSITION_EQUALITY_THRESHOLD = 100
const ELECTRICITY_TRANSITION_EQUALITY_THRESHOLD = 2

var confidence_level float64 = 0.9
var attackLoop = 100
var maxHouseholdsNumber = 80
var NGoRoutine int = 1 // Default number of Go routines
var encryptedSectionNum int
var globalPartyRows = -1
var performanceLoops = 1
var currentDataset = 1  //water(1),electricity(2)
var currentStrategy = 1 //GlobalEntropyHightoLow(1), HouseholdEntropyHightoLow(2), Random(3)
var transitionEqualityThreshold int
var sectionNum int
var usedRandomStartPartyPairs = map[int][]int{}
var blocks []string

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
	fmt.Printf("threshold = %.1f, entropy/transition remain = %.3f,%d\n", 0.0, entropySum, transitionSum)

	encryptedSectionNum = sectionNum
	// var plainSum []float64
	var entropyReduction float64
	var transitionReduction int
	if currentStrategy == 3 {
		blocks = make([]string, len(P)*encryptedSectionNum)
		for pi, _ := range P {
			for i := 0; i < encryptedSectionNum; i++ {
				blocks[pi*encryptedSectionNum+i] = fmt.Sprintf("%d,%d", pi, i)
			}
		}
	}

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

		fmt.Printf("<<<beginning---encryptedSectionNum = [%d]\n", en)

		memberIdentificationAttack(P)               //under current partial encryption
		usedRandomStartPartyPairs = map[int][]int{} //clear map for the next loop
	}

}

func memberIdentificationAttack(P []*party) {
	var attackSuccessNum int
	for a := 0; a < attackLoop; a++ {
		// if a%10 == 0 {
		// fmt.Println("loop: ", a)
		// }
		attackSuccessNum += attackParties(P)
	}
	fmt.Printf("<<<<<<<<<<<EncryptedSectionNum = %v, ASR = %.3f\n", encryptedSectionNum, float64(attackSuccessNum)/float64(attackLoop))
}

func attackParties(P []*party) (attackSuccessNum int) {
	// fmt.Println("starting attack>>>>>>>>>>>>>")
	attackSuccessNum = 0
	randomParty := getRandom(maxHouseholdsNumber)
	// fmt.Println("randomParty: ", randomParty)

	var valid = false
	var randomStart int
	// fmt.Printf("attacking at Party[%d], position[%d]\n", randomParty, randomStart)

	for !valid {
		randomStart = getRandomStart(randomParty)
		var attacker_data_block = P[randomParty].rawInput[randomStart : randomStart+sectionSize]
		if uniqueDataBlock(P, attacker_data_block, randomStart, "rawInput") {
			valid = true
		}
	}

	var attacker_data_block = P[randomParty].rawInput[randomStart : randomStart+sectionSize]

	var matched_households = identifyParty(P, attacker_data_block, randomParty, randomStart)
	if len(matched_households) == 1 {
		attackSuccessNum++
	}

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

func uniqueDataBlock(P []*party, arr []float64, start int, input_type string) bool {
	var unique bool = true

	for _, po := range P {
		var household_data []float64
		if input_type == "rawInput" {
			household_data = po.rawInput
		} else {
			household_data = po.encryptedInput
		}
		for i := 0; i < len(household_data)-sectionSize+1; i++ {
			if i == start {
				continue
			}
			var target = household_data[i : i+sectionSize]
			if reflect.DeepEqual(target, arr) {
				unique = false
				break
			}
		}
		if !unique {
			break
		}
	}
	return unique
}

func identifyParty(P []*party, arr []float64, party int, index int) []int {
	var matched_households = []int{}

	var dataset = P[party].encryptedInput[index : index+sectionSize]

	// Minimum length of the array to be considered a match.
	var min_length int = int(math.Ceil(float64(len(arr)) * confidence_level))

	if min_length == len(arr) {
		// When confidence is 100%, we can compare the arrays straight away.
		if reflect.DeepEqual(dataset, arr) {
			matched_households = append(matched_households, party)
		}
	} else {
		// Otherwise, we need to compare each element of the arrays.
		for i := 0; i < len(dataset)-len(arr)+1; i++ {
			var match = 0
			var mismatch = 0
			// For each element in the dataset, we compare it to the elements in the attack array.
			for j := 0; j < len(arr); j++ {
				// If the elements match, we increment the match counter.
				if reflect.DeepEqual(arr[j], dataset[i+j]) {
					match += 1

				} else {
					// Otherwise, we increment the mismatch counter.
					mismatch += 1
				}
				// If the number of mismatches exceeds the minimum length, we can stop checking.
				if mismatch > min_length {
					break
				}
			}
			if float64(match/len(arr)) >= confidence_level {
				// If the matched portion meets the confidence level, we check if the data block is unique in the encrypted dataset.
				if uniqueDataBlock(P, dataset, index, "encryptedInput") {
					// If it is unique (only one match), we add the party to the list of matched households.
					matched_households = append(matched_households, party)
				}
			}
		}
	}

	return matched_households
}

func convertStrToInt(str string) (num int) {
	num, err := strconv.Atoi(str)
	if err != nil {
		fmt.Println("Conversion error:", err)
		return
	}
	return
}

func markEncryptedSectionsByRandom(en int, P []*party, entropySum float64, transitionSum int) (plainSum []float64, entropyReduction float64, transitionReduction int) {

	entropyReduction = 0.0
	transitionReduction = 0
	plainSum = make([]float64, len(P))

	for i := 0; i < len(P); i++ {
		r := getRandom(len(blocks) - en*(len(P)) - i)
		rStr := strings.Split(blocks[r], ",")
		rParty := convertStrToInt(rStr[0])
		rPos := convertStrToInt(rStr[1])
		//record reductions
		entropyReduction += P[rParty].entropy[rPos]
		transitionReduction += P[rParty].transition[rPos]
		//label
		P[rParty].flag[rPos] = 1
		//exchange
		blocks[r] = blocks[len(blocks)-1-en*(len(P))-i]
	}

	fmt.Printf("threshold = %.1f, entropy/transition remain = %.3f,%d\n", float64(en+1)/float64(encryptedSectionNum), entropySum-entropyReduction, transitionSum-transitionReduction)

	//for each threshold, prepare plainInput&input, and encryptedInput
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

	//for each threshold, prepare plainInput&input, and encryptedInput
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

	//for each threshold, prepare plainInput&input, and encryptedInput
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
