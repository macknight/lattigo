/**
running command:
cd <folder of the project>
go run .\examples\dckks\6ASR\single_ASR_greedy.go 1 2 0 1 20
*/
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
	encryptedInput []float64   //all data after encryption (encrypted value are -0.1) for attack
	flag           []int
	group          []int
	entropy        []float64 //entropy for block
	transition     []float64

	greedyInputs [][]float64
	greedyFlags  [][]int
}

type task struct {
	wg          *sync.WaitGroup
	op1         *rlwe.Ciphertext
	op2         *rlwe.Ciphertext
	res         *rlwe.Ciphertext
	elapsedtask time.Duration
}

const MAX_PARTY_ROWS = 10240 //241920
const sectionSize = 1024     // element number within a section
const STRATEGY_GLOBAL = 1
const STRATEGY_HOUSEHOLD = 2
const STRATEGY_RANDOM = 3
const DATASET_WATER = 1
const DATASET_ELECTRICITY = 2
const WATER_TRANSITION_EQUALITY_THRESHOLD = 100
const ELECTRICITY_TRANSITION_EQUALITY_THRESHOLD = 2

var atdSize int // records number of attack data block
var min_percent_matched = 100
var GLOBAL_ATTACK_LOOP = 2000
var LOCAL_ATTACK_LOOP = 2000

var maxHouseholdsNumber = 80

var NGoRoutine int = 1 // Default number of Go routines
var encryptedSectionNum int
var globalPartyRows = -1
var performanceLoops = 1

var currentStrategy int = 1 //Global(1), Household(2), Random(3)
var currentDataset int = 1  //water(1),electricity(2)
var uniqueATD int = 0       // unique attacker data, 1 for true, 0 for false
var currentTarget = 2       //entropy(1),transition(2)

var encryptionRatio = 20 //20%

var transitionEqualityThreshold int
var sectionNum int
var usedRandomStartPartyPairs = map[int][]int{}
var usedHouses = map[int]int{}
var asrList []float64
var edgeNumberArray = []int{}

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
		uniqueATD = args[2]
		currentTarget = args[3]
		encryptionRatio = args[4]
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
	if uniqueATD == 0 {
		fmt.Println("Unique Attacker Block: False")
	} else {
		fmt.Println("Unique Attacker Block: True")
	}
	if currentTarget == 1 {
		fmt.Println("Target: Entropy based")
	} else {
		fmt.Println("Target: Transition based")
	}
	fmt.Println("encryptionRatio:", encryptionRatio)

	fmt.Println("SE threshold ", 0.01)
	fmt.Println("Global Attack Loop: ", GLOBAL_ATTACK_LOOP)
	fmt.Println("Number of Households: ", maxHouseholdsNumber)
	fmt.Println("Encryption ratio: 60%")

	fmt.Println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

	rand.Seed(time.Now().UnixNano())
	start := time.Now()
	fileList := []string{}
	var err error
	paramsDef := ckks.PN10QP27CI
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
	var pathFormat string
	var path string
	if strings.Contains(wd, "examples") {
		pathFormat = filepath.Join("..", "..", "..", "examples", "datasets", "%s", "households_%d")
	} else {
		pathFormat = filepath.Join("examples", "datasets", "%s", "households_%d")
	}
	if currentDataset == DATASET_WATER {
		path = fmt.Sprintf(pathFormat, "water", MAX_PARTY_ROWS)
		transitionEqualityThreshold = WATER_TRANSITION_EQUALITY_THRESHOLD
	} else { //electricity
		path = fmt.Sprintf(pathFormat, "electricity", MAX_PARTY_ROWS)
		transitionEqualityThreshold = ELECTRICITY_TRANSITION_EQUALITY_THRESHOLD
	}

	folder := filepath.Join(wd, path)
	fmt.Println("wd:", wd)
	fmt.Println("path:", path)
	fmt.Println("folder:", folder)

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
	fmt.Printf("fileList:%d\n", len(fileList))

	for atdSize = 3; atdSize <= 48; atdSize += 3 {
		for percent := 100; percent >= 100; percent -= 10 { //TODO: matching proportion like 50% ATD is matched
			min_percent_matched = percent
			for selectedNum := maxHouseholdsNumber; selectedNum <= maxHouseholdsNumber; selectedNum += 5 {
				maxHouseholdsNumber = selectedNum
				processGreedy(fileList[:selectedNum], params)
			}
		}
	}

	fmt.Printf("Main() Done in %s \n", time.Since(start))
}

// main start
func processGreedy(fileList []string, params ckks.Parameters) {
	P := genparties(params, fileList)
	genInputs(P)
	intializeEdgeRelated(P)
	edgeSize := len(P) * (len(P) - 1) * sectionNum * sectionNum / 2
	edges := make([]float64, edgeSize)

	markedFirstHousehold := -1
	markedFirstSection := -1
	markedSecondHousehold := -1
	markedSecondSection := -1
	markedNumbers := 0
	previousMarkedNumbers := 0

	thresholdNumber := len(P) * globalPartyRows * encryptionRatio / 100

	for markedNumbers < thresholdNumber {
		maxUniquenessScore := -1.0
		for edge_index := range edges {
			p_index_first, s_index_first, p_index_second, s_index_second := getDetailedBlocksForEdge(edge_index, len(P), sectionNum)

			edges[edge_index] = calculateUniquenessBetweenBlocks(P, p_index_first, s_index_first, p_index_second, s_index_second)

			if edges[edge_index] > maxUniquenessScore {
				maxUniquenessScore = edges[edge_index]
				markedFirstHousehold = p_index_first
				markedFirstSection = s_index_first
				markedSecondHousehold = p_index_second
				markedSecondSection = s_index_second
			}
		}
		// fmt.Println("edges:", edges)
		previousMarkedNumbers = markedNumbers
		markedNumbers = greedyMarkBlocks(markedNumbers, thresholdNumber, P, markedFirstHousehold, markedFirstSection, markedSecondHousehold, markedSecondSection)
		if markedNumbers == previousMarkedNumbers {
			break
		}
	}
	// fmt.Println("markedNumbers:", markedNumbers)
	// fmt.Println("thresholdNumber ", thresholdNumber)

	greedyEncryptBlocks(P)
	memberIdentificationAttack(P) //under current partial encryption
}

func greedyEncryptBlocks(P []*party) {
	for _, po := range P {
		for j := 0; j < globalPartyRows; j++ {
			if po.greedyFlags[j/sectionSize][j%sectionSize] == 1 {
				po.encryptedInput[j] = -0.1
			} else {
				po.encryptedInput[j] = po.rawInput[j]
			}
		}
	}
}

func greedyMarkBlocks(markedNumbers, thresholdNumber int, P []*party, markedFirstHousehold, markedFirstSection, markedSecondHousehold, markedSecondSection int) int {
	firstBlock := P[markedFirstHousehold].greedyInputs[markedFirstSection]
	secondBlock := P[markedSecondHousehold].greedyInputs[markedSecondSection]
	firstBlockFlags := P[markedFirstHousehold].greedyFlags[markedFirstSection]
	secondBlockFlags := P[markedSecondHousehold].greedyFlags[markedSecondSection]
	for i := 0; i < sectionSize; i++ {
		if firstBlockFlags[i] == 0 && secondBlockFlags[i] == 0 {
			if firstBlock[i] != secondBlock[i] {
				firstBlockFlags[i] = 1
				markedNumbers++
				if markedNumbers == thresholdNumber {
					break
				}
				secondBlockFlags[i] = 1
				markedNumbers++
				if markedNumbers == thresholdNumber {
					break
				}
			}
		} else if firstBlockFlags[i] == 0 && secondBlockFlags[i] == 1 {
			if firstBlock[i] != secondBlock[i] {
				firstBlockFlags[i] = 1
				markedNumbers++
				if markedNumbers == thresholdNumber {
					break
				}
			}
		} else if firstBlockFlags[i] == 1 && secondBlockFlags[i] == 0 {
			if firstBlock[i] != secondBlock[i] {
				secondBlockFlags[i] = 1
				markedNumbers++
				if markedNumbers == thresholdNumber {
					break
				}
			}
		}
	}

	return markedNumbers
}

func calculateUniquenessBetweenBlocks(P []*party, p_index_first, s_index_first, p_index_second, s_index_second int) float64 {
	firstBlock := P[p_index_first].greedyInputs[s_index_first]
	secondBlock := P[p_index_second].greedyInputs[s_index_second]
	firstBlockFlags := P[p_index_first].greedyFlags[s_index_first]
	secondBlockFlags := P[p_index_second].greedyFlags[s_index_second]

	// P_U:possibility of uniqueness
	// decoratedValues holds 2 decimal precision
	// P_U(0,0)=0, P_U(0,1)=1, P_U(0,X)=0.9, P_U(X,X)=0.9, 0.9 is empirical cause most electricity values range from 0.0-0.9 (10 options)
	uniquenessScore := 0.0
	for i := 0; i < sectionSize; i++ {
		if firstBlockFlags[i] == 1 || secondBlockFlags[i] == 1 {
			uniquenessScore += 0.9
		} else if firstBlock[i] != secondBlock[i] {
			//non equal, unique
			uniquenessScore += 1
		} else {
			//equal, non unique
			uniquenessScore += 0
		}
	}

	return uniquenessScore
}

func intializeEdgeRelated(P []*party) {
	edgeNumberArray = make([]int, len(P)) //defaults to 0
	for i := range edgeNumberArray {
		num := 0
		for j := 1; j < len(P)-i; j++ {
			num += sectionNum * sectionNum
		}
		edgeNumberArray[i] = num
	}
	// fmt.Println("edgeNumberArray:", edgeNumberArray)
}

func getDetailedBlocksForEdge(edge_index, householdNumber, sectionNumber int) (int, int, int, int) {
	p_index_first, s_index_first, p_index_second, s_index_second := -1, -1, -1, -1
	sectionNumberSqured := sectionNumber * sectionNumber

	sum := 0
	for i := 0; i < len(edgeNumberArray); i++ {
		previousSum := sum
		sum += edgeNumberArray[i]
		if sum > edge_index {
			p_index_first = i
			edge_index -= previousSum
			break
		}
	}

	sum = 0
	for i := p_index_first + 1; i < householdNumber; i++ {
		previousSum := sum
		sum += sectionNumberSqured
		if sum > edge_index {
			p_index_second = i
			edge_index -= previousSum
			break
		}
	}

	sum = 0
	for i := 0; i < sectionNumber; i++ {
		previousSum := sum
		sum += sectionNumber
		if sum > edge_index {
			s_index_first = i
			edge_index -= previousSum
			break
		}
	}

	s_index_second = edge_index

	return p_index_first, s_index_first, p_index_second, s_index_second
}

func memberIdentificationAttack(P []*party) { //TODO:atd size
	var std float64
	var mean float64
	var standard_error float64
	asrList = []float64{}
	for attackLoop := 0; attackLoop < GLOBAL_ATTACK_LOOP; attackLoop++ {
		attackSuccessCount := 0
		attackCount := 0
		for ; attackCount < LOCAL_ATTACK_LOOP; attackCount++ {
			if attackParties(P) {
				attackSuccessCount++
			}
		}
		usedRandomStartPartyPairs = map[int][]int{} //clear map for each global attack loop
		asr := float64(attackSuccessCount) / float64(attackCount)
		asrList = append(asrList, asr)
		std, mean = calculateStandardDeviation(asrList)
		standard_error = std / math.Sqrt(float64(len(asrList)))
		if standard_error <= 0.01 && attackLoop >= 100 {
			attackLoop++
			break
		}
		fmt.Printf("Global Attack Loop:%d\nASR: %.3f, std:%.3f, mean ASR: %.3f, standard error: %.3f\n=====\n", attackLoop, asr, std, mean, standard_error)
	}

	fmt.Println("Attack Summary:")
	fmt.Printf("EncryptionRatio: %d, atdSize: %d, Number of households: %d, mean ASR: %.3f, standard error: %.3f\n", encryptionRatio, atdSize, maxHouseholdsNumber, mean, standard_error)
	fmt.Println("asrList:", asrList)
}

func attackParties(P []*party) (result bool) {
	// Generate a leaked data block and simulate attack
	var valid = false
	var randomParty int
	var randomStart int

	if uniqueATD == 0 {
		randomParty = getRandom(maxHouseholdsNumber)
		randomStart = getRandomStart(randomParty)
	} else {
		for !valid {
			randomParty = getRandom(maxHouseholdsNumber)
			randomStart = getRandomStart(randomParty)
			var attacker_data_block = P[randomParty].rawInput[randomStart : randomStart+atdSize]
			if uniqueDataBlock(P, attacker_data_block, randomParty, randomStart, "rawInput") {
				valid = true
			}
		}
	}
	// fmt.Printf("randomParty:%d,randomStart:%d\n", randomParty, randomStart)
	var attacker_data_block = P[randomParty].rawInput[randomStart : randomStart+atdSize]

	var matched_households = identifyParty(P, attacker_data_block, randomParty, randomStart)
	if len(matched_households) == 1 && matched_households[0] == randomParty {
		return true
	} else {
		return false
	}
}

func getRandomStart(party int) int {
	// Return a unused random start for the party
	var valid bool = false

	var randomStart int

	for !valid {
		randomStart = getRandom(MAX_PARTY_ROWS - atdSize)
		if !contains(party, randomStart) {
			usedRandomStartPartyPairs[party] = append(usedRandomStartPartyPairs[party], randomStart)
			valid = true
		}
	}
	return randomStart
}

func contains(party int, randomStart int) bool {
	// Check if the party has used the random start before
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

func uniqueDataBlock(P []*party, arr []float64, party int, index int, input_type string) bool {
	// Check if the data block is unique in the dataset
	var unique bool = true

	for pi, po := range P {
		if pi == party {
			continue
		}
		var household_data []float64
		if input_type == "rawInput" {
			household_data = po.rawInput
		} else {
			household_data = po.encryptedInput
		}
		for i := 0; i < len(household_data)-atdSize+1; i++ {
			var target = household_data[i : i+atdSize]
			if reflect.DeepEqual(target, arr) {
				unique = false
				usedRandomStartPartyPairs[pi] = append(usedRandomStartPartyPairs[pi], i)
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
	// Identify the party based on the arr data block
	var matched_households = []int{}

	var dataset = P[party].encryptedInput[index : index+atdSize]

	// Minimum length of the array to be considered a match.
	var min_length int = int(math.Ceil(float64(len(arr)) * float64(min_percent_matched) / 100))

	if min_length == len(arr) {
		// When percent matched required is 100%, we can compare the arrays straight away.
		if uniqueATD == 0 {
			// If we are not using unique data blocks, need to check if it's an unique match
			if reflect.DeepEqual(dataset, arr) && uniqueDataBlock(P, dataset, party, index, "encryptedInput") {
				matched_households = append(matched_households, party)
			}
		} else {
			if reflect.DeepEqual(dataset, arr) {
				matched_households = append(matched_households, party)
			}
		}
	} else {
		// Otherwise, we need to compare each element of the arrays to see if matching percent meets the threshold.
		var match int = 0
		var mismatch int = 0
		// For each element in the dataset, we compare it to the elements in the attack array.
		for i := 0; i < len(arr); i++ {
			// If the elements match, we increment the match counter.
			if reflect.DeepEqual(arr[i], dataset[i]) {
				match += 1

			} else {
				// Otherwise, we increment the mismatch counter.
				mismatch += 1
			}
			// If the number of mismatches exceeds the allowable amount, we can stop checking.
			if mismatch > (len(arr) - min_length) {
				break
			}
		}

		if float64(match)/float64(len(arr)) >= float64(min_percent_matched)/100.0 {
			var pos_matches = [][]float64{}
			// If the matched portion meets the percent matched, we check if the data block is unique in the encrypted dataset.
			if atdSize <= sectionSize {
				// if the atd is <= to section, the possible encrypted portion can only be at the start or end of the section.
				var pos_match1 = P[party].encryptedInput[index : index+min_length]
				var post_match2 = P[party].encryptedInput[index+atdSize-min_length : index+atdSize]
				pos_matches = append(pos_matches, pos_match1, post_match2)
			} else {
				// Otherwise, possible positions of encrypted portion could be anywhere in the section.
				for i := 0; i <= len(arr)-min_length; i++ {
					var pos_match = P[party].encryptedInput[index+i : index+min_length+i]
					pos_matches = append(pos_matches, pos_match)
				}
			}
			if uniqueDataBlocks(P, pos_matches, party, index, min_length) {
				// If it is unique (only one match), we add the party to the list of matched households.
				matched_households = append(matched_households, party)
			}
		}
	}

	return matched_households
}

func uniqueDataBlocks(P []*party, pos_matches [][]float64, party int, index int, min_length int) bool {
	// Check if the data blocks is unique in the dataset
	var unique bool = true

	for pn, po := range P {
		if pn == party {
			continue
		}
		var household_data []float64 = po.encryptedInput
		for i := 0; i < len(household_data)-min_length+1; i++ {
			var target = household_data[i : i+min_length]
			for _, pos_match := range pos_matches {
				if reflect.DeepEqual(target, pos_match) {
					unique = false
					break
				}
			}
		}
		if !unique {
			break
		}
	}
	return unique
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

		if pi == 0 {
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
		po.encryptedInput = make([]float64, globalPartyRows)

		po.flag = make([]int, sectionNum)
		po.entropy = make([]float64, sectionNum)
		po.transition = make([]float64, sectionNum)
		po.group = make([]int, sectionSize)

		po.greedyInputs = make([][]float64, sectionNum)
		for i := range po.greedyInputs {
			po.greedyInputs[i] = make([]float64, sectionSize)
		}
		po.greedyFlags = make([][]int, sectionNum)
		for i := range po.greedyFlags {
			po.greedyFlags[i] = make([]int, sectionSize)
		}

		delta := 0.0
		for i := range po.rawInput {
			realValue := math.Round(partyRows[i]*1000) / 1000  // hold 3 decimal places
			decoratedValue := math.Round(partyRows[i]*10) / 10 // decrease data uniqueness, very important, together with atdSize
			delta += decoratedValue - realValue

			po.rawInput[i] = decoratedValue
			po.greedyInputs[i/sectionSize][i%sectionSize] = decoratedValue
			if i == len(po.rawInput)-1 {
				po.rawInput[i] -= delta
				po.greedyInputs[i/sectionSize][i%sectionSize] -= delta
			}

			val, exists := frequencyMap[po.rawInput[i]]
			if exists {
				val++
			} else {
				val = 1
			}
			frequencyMap[po.rawInput[i]] = val

			expSummation[pi] += po.rawInput[i]
		} //each line of one person
		// os.Exit(0)

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

	//max,min based on currentTarget
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

func calculateStandardDeviation(numbers []float64) (float64, float64) {
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

	return standardDeviation, mean
}
