package main

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lazybeaver/entropy"
	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/drlwe"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) <= equalityThreshold
}

func check(err error) {
	if err != nil {
		panic(err)
	}
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

	rawInput   []float64 //all data
	input      []float64 //data of encryption
	plainInput []float64 //data of plain
	flag       []int
	group      []int
	entropy    []float64
	transition []int
}

const pathFormat = "C:\\Users\\23304161\\source\\Datasets\\electricity\\london\\halfhourly_dataset\\households_%d"
const fileFormat = "C:\\Users\\23304161\\source\\Datasets\\electricity\\london\\halfhourly_dataset\\households_%d\\%s"

const FILE_ROWS = 20480
const MAX_PARTY_ROWS = 20480 //241920
const equalityThreshold = 2
const sectionSize = 2048 // element number within a section

var NGoRoutine int = 1 // Default number of Go routines
var encryptedSectionNum int
var sectionNum int

func main() {
	start := time.Now()

	loop := 1
	maxHouseholdsNumber := 80
	fileList := []string{}
	var err error
	paramsDef := ckks.PN11QP54CI // block size = 4096
	params, err := ckks.NewParametersFromLiteral(paramsDef)
	check(err)
	if err != nil {
		fmt.Println("Error:", err)
	}

	folder := fmt.Sprintf(pathFormat, FILE_ROWS)
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
	for i := 0; i < loop; i++ {
		process(fileList[:maxHouseholdsNumber], params)
	}

	fmt.Printf("Main() Done in %s \n", time.Since(start))
}

//main start
func process(fileList []string, params ckks.Parameters) {

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := genparties(params, fileList)

	//getInputs read the data file
	// Inputs & expected result, cleartext result
	_, _, _, _, _, minEntropy, maxEntropy, entropySum, transitionSum := genInputs(params, P) //globalPartyRows rows

	histogram := genHistogram(P, minEntropy, maxEntropy)
	fmt.Printf(">>>>>>>Electricity Entropy Histograme:\n")
	for i := 0; i < len(histogram); i++ {
		fmt.Printf("[%d]: %d\n", i, histogram[i])
	}

	//mark blocks needing to be encrypted
	fmt.Printf("transition equalityThreshold: %d\n", equalityThreshold)
	fmt.Printf("entropy remain[initial] = %.3f; transition remain[initial] = %d\n", entropySum, transitionSum)

	markEncryptedSections(P, 1.0, entropySum, transitionSum)
}

//main end

func markEncryptedSections(P []*party, threshold, entropySum float64, transitionSum int) {

	encryptedSectionNum = int(math.Floor(float64(sectionNum) * threshold))
	for i := 0; i < encryptedSectionNum; i++ {
		previousEntropySum := entropySum
		previousTransitionSum := transitionSum
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
			entropySum -= po.entropy[index]
			transitionSum -= po.transition[index]
		}
		fmt.Printf("entropy remain[%d] = %.3f (diff: %.3f), transition remain[%d] = %d (diff: %d)\n", i, entropySum, previousEntropySum-entropySum, i, transitionSum, previousTransitionSum-transitionSum)
	}
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
	fmt.Println("reading without buffer:")
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	// fmt.Println("data:", string(data))
	dArray := strings.Split(string(data), "\n")
	fmt.Println("original CSV size:", len(dArray))
	// dArray2 := dArray[1 : len(dArray)-1]
	// fmt.Println("data CSV size:", len(dArray)) //[0]..[241919]
	return dArray[:len(dArray)-1]
}

//trim csv
func resizeCSV(filename string) []float64 {

	filepath := fmt.Sprintf(fileFormat, FILE_ROWS, filename)
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
	rand.Seed(time.Now().UnixNano())
	randNumber = rand.Intn(numberRange) //[0, numberRange-1]

	return
}

const HISTOGRAM_CATEGORY_SIZE = 10

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
func genInputs(params ckks.Parameters, P []*party) (globalPartyRows int, expSummation, expAverage, expDeviation, plainSum []float64, minEntropy, maxEntropy, entropySum float64, transitionSum int) {

	sectionNum = 0
	// randNumber := -1
	globalPartyRows = -1
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
			plainSum = make([]float64, len(P))
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

		// po.input = make([]float64, 0)      //flagCount*sectionSize
		// po.plainInput = make([]float64, 0) //lenPartyRows-flagCount*sectionSize
		// for i := 0; i < lenPartyRows; i++ {
		// 	if po.flag[i/sectionSize] == -1 {
		// 		po.input = append(po.input, po.rawInput[i])
		// 	} else {
		// 		plainSum[pi] += po.rawInput[i]
		// 		po.plainInput = append(po.plainInput, po.rawInput[i])
		// 	}
		// }

	} // each person

	return
}
