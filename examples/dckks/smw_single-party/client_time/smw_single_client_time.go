package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

var NGoRoutine int = 1 // Default number of Go routines
var lock sync.Mutex

// Marshal is a function that marshals the object into an
// io.Reader.
// By default, it uses the JSON marshaller.
var Marshal = func(v interface{}) (io.Reader, error) {
	b, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

// Unmarshal is a function that unmarshals the data from the
// reader into the specified value.
// By default, it uses the JSON unmarshaller.
var Unmarshal = func(r io.Reader, v interface{}) error {
	return json.NewDecoder(r).Decode(v)
}

// Save saves a representation of v to the file at path.
func Save(path string, v interface{}) error {
	lock.Lock()
	defer lock.Unlock()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := Marshal(v)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, r)
	return err
}

// Load loads the file at path into v.
// Use os.IsNotExist() to see if the returned error is due
// to the file being missing.
func Load(path string, v interface{}) error {
	lock.Lock()
	defer lock.Unlock()
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return Unmarshal(f, v)
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
	id         int
	folderName string
	sk         *rlwe.SecretKey
	input      []float64
}

var elapsedSKGParty time.Duration
var elapsedPKGParty time.Duration
var elapsedRKGParty time.Duration
var elapsedRTGParty time.Duration

var elapsedEncryptParty time.Duration
var elapsedDecParty time.Duration

// var pathFormat = "C:\\Users\\23304161\\source\\smw\\%s\\House_10sec_1month_%d.csv"
var pathFormat = "./%s/House_10sec_1month_%d.csv"

func main() {
	start := time.Now()

	loop := 1
	maximumLenPartyRows := 8640
	folderName := "200Houses_10s_1month_highVD"

	householdIDs := []int{}
	minHouseholdID := 1
	maxHouseholdID := 1

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

	fmt.Println("client time:~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	//public key & relinearization key & rotation key
	fmt.Printf("*****Amortized SKG Time: %s\n", time.Duration(elapsedSKGParty.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized PKG Time: %s\n", time.Duration(elapsedPKGParty.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized RKG Time: %s\n", time.Duration(elapsedRKGParty.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized RTG Time: %s\n", time.Duration(elapsedRTGParty.Nanoseconds()/int64(loop)))

	//single operation, independent of households' size
	fmt.Printf("*****Amortized Encrypt Time: %s\n", time.Duration(elapsedEncryptParty.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized Decrypt Time: %s\n", time.Duration(elapsedDecParty.Nanoseconds()/int64(loop)))

	fmt.Printf("Main() Done in %s \n", time.Since(start))

	PrintMemUsage()
}

//main start
func process(householdIDs []int, maximumLenPartyRows int, folderName string, params ckks.Parameters) {
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
	globalPartyRows, _, _, _ := genInputs(params, P, maximumLenPartyRows) //globalPartyRows rows

	var rlk *rlwe.RelinearizationKey
	elapsedRKGParty += runTimed(func() {
		rlk = tkgen.GenRelinearizationKey(tsk, 1)
	})

	rotations := params.RotationsForInnerSumLog(1, globalPartyRows)
	var rotk *rlwe.RotationKeySet
	elapsedRTGParty += runTimed(func() {
		rotk = tkgen.GenRotationKeysForRotations(rotations, false, tsk)
	})

	fmt.Println(unsafe.Sizeof(rlk))
	fmt.Println(unsafe.Sizeof(rotk))

	// if err := Save("./single_tpk.tmp", tpk); err != nil {
	// 	log.Fatalln(err)
	// }
	// if err := Save("./single_tsk.tmp", tsk); err != nil {
	// 	log.Fatalln(err)
	// }
	// if err := Save("./single_rlk.tmp", rlk); err != nil {
	// 	log.Fatalln(err)
	// }
	// if err := Save("./single_rotk.tmp", rotk); err != nil {
	// 	log.Fatalln(err)
	// }

	decryptor := ckks.NewDecryptor(params, tsk)
	encoder := ckks.NewEncoder(params)

	//generate ciphertexts
	encInputsAverage, encInputsNegative, encInputsSummation := encPhase(params, P, tpk, encoder)

	encSummationOuts := make([]*ckks.Ciphertext, 0)
	encDeviationOuts := make([]*ckks.Ciphertext, 0)

	// summation
	for _, encInputSummation := range encInputsSummation {
		encSummationOuts = append(encSummationOuts, encInputSummation)
	}

	// deviation
	for i, _ := range encInputsAverage {
		encDeviationOuts = append(encDeviationOuts, encInputsNegative[i])
	}

	// Decrypt & Check the result
	ptresDeviation := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())
	ptresSummation := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())

	// print summation
	for i, _ := range encSummationOuts {
		decryptor.Decrypt(encSummationOuts[i], ptresSummation) //ciphertext->plaintext
	}

	// print deviation
	for i, _ := range encDeviationOuts {
		elapsedDecParty += runTimedParty(func() {
			decryptor.Decrypt(encDeviationOuts[i], ptresDeviation) //ciphertext->plaintext
		}, len(P))
	}
}

//main end

// encPhase to get []ciphertext
func encPhase(params ckks.Parameters, P []*party, pk *rlwe.PublicKey, encoder ckks.Encoder) (encInputsAverage, encInputsNegative, encInputsSummation []*ckks.Ciphertext) {

	encInputsAverage = make([]*ckks.Ciphertext, len(P))
	encInputsNegative = make([]*ckks.Ciphertext, len(P))
	encInputsSummation = make([]*ckks.Ciphertext, len(P))

	for i := range encInputsAverage {
		encInputsAverage[i] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
		encInputsNegative[i] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
		encInputsSummation[i] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
	}

	// Each party encrypts its input vector
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

	return
}

//generate parties
func genparties(params ckks.Parameters, folderName string, householdIDs []int) []*party {
	N := len(householdIDs)
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
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	dArray := strings.Split(string(data), "\n")
	dArray2 := dArray[1 : len(dArray)-1]
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

// PrintMemUsage outputs the current, total and OS memory being used. As well as the number
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
