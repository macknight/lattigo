package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/dckks"
	"github.com/tuneinsight/lattigo/v3/drlwe"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"
)

// Check the result
const float64EqualityThreshold = 1e-4

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

var elapsedEncryptParty time.Duration
var elapsedEncryptCloud time.Duration
var elapsedCKGCloud time.Duration
var elapsedCKGParty time.Duration
var elapsedSKGParty time.Duration

var elapsedRKGCloud time.Duration
var elapsedRKGParty time.Duration
var elapsedRTGCloud time.Duration
var elapsedRTGParty time.Duration
var elapsedPCKSCloud time.Duration
var elapsedPCKSParty time.Duration
var elapsedDecParty time.Duration

var spTotalMemory uint64
var a uint64
var b uint64

// var pathFormat = "C:\\Users\\23304161\\source\\smw\\%s\\House_10sec_1month_%d.csv"

var pathFormat = "./%s/House_10sec_1month_%d.csv"

func main() {
	start := time.Now()

	loop := 1
	maximumLenPartyRows := 8640
	folderName := "200Houses_10s_1month_highVD"

	householdIDs := []int{}
	minHouseholdID := 1
	maxHouseholdID := 50

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

	fmt.Println("client & protocol time~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
	//contains cloud & party. cloud is dependent of households' size; party isn't
	fmt.Printf("*****Amortized SKG Time: %s(party)\n", time.Duration(elapsedSKGParty.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized CKG Time: %s(cloud); %s(party)\n", time.Duration(elapsedCKGCloud.Nanoseconds()/int64(loop)), time.Duration(elapsedCKGParty.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized RKG Time: %s(cloud); %s(party)\n", time.Duration(elapsedRKGCloud.Nanoseconds()/int64(loop)), time.Duration(elapsedRKGParty.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized RTG Time: %s(cloud); %s(party)\n", time.Duration(elapsedRTGCloud.Nanoseconds()/int64(loop)), time.Duration(elapsedRTGParty.Nanoseconds()/int64(loop)))
	//pcksphase method is called 2*len(householdsID) for each loop
	fmt.Printf("*****Amortized PCKS Time: %s(cloud); %s(party)\n", time.Duration(elapsedPCKSCloud.Nanoseconds()/int64(loop*2*len(householdIDs))), time.Duration(elapsedPCKSParty.Nanoseconds()/int64(loop*2*len(householdIDs))))

	//single operation, independent of households' size
	fmt.Printf("*****Amortized Encrypt Time: %s\n", time.Duration(elapsedEncryptParty.Nanoseconds()/int64(loop)))
	fmt.Printf("*****Amortized Decrypt Time: %s\n", time.Duration(elapsedDecParty.Nanoseconds()/int64(loop)))

	fmt.Printf("Main() Done in %s \n", time.Since(start))

	PrintMemUsage()
}

//main start
func process(householdIDs []int, maximumLenPartyRows int, folderName string, params ckks.Parameters) {
	var err error

	// householdIDs := []int{6, 7, 8} // using suffix IDs of the csv files
	// Largest for n=8192: 512 parties

	crs, err := utils.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	check(err)
	encoder := ckks.NewEncoder(params)
	// Target private and public keys
	tkgen := ckks.NewKeyGenerator(params)
	tsk, tpk := tkgen.GenKeyPair()

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := genparties(params, folderName, householdIDs)

	// Inputs & expected result, cleartext result
	genInputs(params, P, maximumLenPartyRows) //globalPartyRows rows

	// 1) Collective public key generation
	pk := ckgphase(params, crs, P)

	// 2) Collective relinearization key generation
	rlk := rkgphase(params, crs, P)
	// 3) Collective rotation key generation
	rotk := rtkgphase(params, crs, P)

	fmt.Println(unsafe.Sizeof(rlk))
	fmt.Println(unsafe.Sizeof(rotk))

	// if err := Save("./multi_pk.tmp", pk); err != nil {
	// 	log.Fatalln(err)
	// }
	// if err := Save("./multi_rlk.tmp", rlk); err != nil {
	// 	log.Fatalln(err)
	// }
	// if err := Save("./multi_rotk.tmp", rotk); err != nil {
	// 	log.Fatalln(err)
	// }

	//generate ciphertexts
	encInputsAverage, encInputsNegative, encInputsSummation := encPhase(params, P, pk, encoder)

	encSummationOuts := make([]*ckks.Ciphertext, 0)
	encDeviationOuts := make([]*ckks.Ciphertext, 0)

	// summation
	for _, encInputSummation := range encInputsSummation {
		encSummationOuts = append(encSummationOuts, pcksPhase(params, tpk, encInputSummation, P))
	}

	// deviation
	for i, _ := range encInputsAverage {
		encDeviationOuts = append(encDeviationOuts, pcksPhase(params, tpk, encInputsNegative[i], P)) // cpk -> tpk
	}

	// Decrypt & Check the result
	a = currentTotalAlloc()
	decryptor := ckks.NewDecryptor(params, tsk)
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
	b = currentTotalAlloc()
	// record memory for decryption
	spTotalMemory += b - a

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

	elapsedEncryptCloud += time.Duration(0)
	return
}

//generate parties
func genparties(params ckks.Parameters, folderName string, householdIDs []int) []*party {
	N := len(householdIDs)
	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := make([]*party, N)

	for i, id := range householdIDs {
		pi := &party{}
		elapsedSKGParty += runTimedParty(func() {
			pi.sk = ckks.NewKeyGenerator(params).GenSecretKey()
			// if i == 0 {
			// 	if err := Save("./multi_sk0.tmp", pi.sk); err != nil {
			// 		log.Fatalln(err)
			// 	}
			// }
		}, N)
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

//key switching phase
func pcksPhase(params ckks.Parameters, tpk *rlwe.PublicKey, encRes *ckks.Ciphertext, P []*party) (encOut *ckks.Ciphertext) {

	pcks := dckks.NewPCKSProtocol(params, 3.19)

	for _, pi := range P {
		pi.pcksShare = pcks.AllocateShare(params.MaxLevel())
	}

	elapsedPCKSParty += runTimedParty(func() {
		for _, pi := range P {
			pcks.GenShare(pi.sk, tpk, encRes.Value[1], pi.pcksShare)
		}
	}, len(P))

	pcksCombined := pcks.AllocateShare(params.MaxLevel())
	// 	if err := Save("./multi_pcksCombined.tmp", pcksCombined); err != nil {
	// 		log.Fatalln(err)
	// 	}
	encOut = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
	a = currentTotalAlloc()
	elapsedPCKSCloud += runTimed(func() {
		for _, pi := range P {
			pcks.AggregateShare(pi.pcksShare, pcksCombined, pcksCombined)
			// if i == 0 {
			// 	if err := Save("./multi_pcksCombined_aggregated.tmp", pcksCombined); err != nil {
			// 		log.Fatalln(err)
			// 	}
			// }
		}
		pcks.KeySwitch(encRes, pcksCombined, encOut)

	})
	b = currentTotalAlloc()
	spTotalMemory += b - a

	return

}

//generate collective rotation key
func rtkgphase(params ckks.Parameters, crs utils.PRNG, P []*party) *rlwe.RotationKeySet {

	rtg := dckks.NewRotKGProtocol(params) // Rotation keys generation

	for _, pi := range P {
		pi.rtgShare = rtg.AllocateShare()
	}

	galEls := params.GaloisElementsForRowInnerSum()

	rotKeySet := ckks.NewRotationKeySet(params, galEls)
	for _, galEl := range galEls {
		rtgShareCombined := rtg.AllocateShare()
		// if err := Save("./multi_rtgShareCombined.tmp", rtgShareCombined); err != nil {
		// 	log.Fatalln(err)
		// }
		crp := rtg.SampleCRP(crs)
		elapsedRTGParty += runTimedParty(func() {
			for _, pi := range P {
				rtg.GenShare(pi.sk, galEl, crp, pi.rtgShare)
			}
		}, len(P))

		a = currentTotalAlloc()
		elapsedRTGCloud += runTimed(func() {
			for _, pi := range P {
				rtg.AggregateShare(pi.rtgShare, rtgShareCombined, rtgShareCombined)
				// if i == 0 {
				// 	if err := Save("./multi_rtgShareCombined_aggregated.tmp", rtgShareCombined); err != nil {
				// 		log.Fatalln(err)
				// 	}
				// }
			}
			rtg.GenRotationKey(rtgShareCombined, crp, rotKeySet.Keys[galEl])
		})
		b = currentTotalAlloc()
		spTotalMemory += b - a
	}

	return rotKeySet
}

//generate collective relinearization key
func rkgphase(params ckks.Parameters, crs utils.PRNG, P []*party) *rlwe.RelinearizationKey {

	rkg := dckks.NewRKGProtocol(params) // Relineariation key generation
	_, rkgCombined1, rkgCombined2 := rkg.AllocateShare()
	// if err := Save("./multi_rkgCombined1.tmp", rkgCombined1); err != nil {
	// 	log.Fatalln(err)
	// }
	// if err := Save("./multi_rkgCombined2.tmp", rkgCombined2); err != nil {
	// 	log.Fatalln(err)
	// }

	for _, pi := range P {
		pi.rlkEphemSk, pi.rkgShareOne, pi.rkgShareTwo = rkg.AllocateShare()
	}

	////////////////////////////////////////////
	crp := rkg.SampleCRP(crs)
	elapsedRKGParty += runTimedParty(func() {
		for _, pi := range P {
			rkg.GenShareRoundOne(pi.sk, crp, pi.rlkEphemSk, pi.rkgShareOne)
		}
	}, len(P))

	a = currentTotalAlloc()
	elapsedRKGCloud += runTimed(func() {
		for _, pi := range P {
			rkg.AggregateShare(pi.rkgShareOne, rkgCombined1, rkgCombined1)
			// if err := Save("./multi_rkgCombined1_aggregated.tmp", rkgCombined1); err != nil {
			// 	log.Fatalln(err)
			// }
		}
	})
	b = currentTotalAlloc()
	spTotalMemory += b - a
	////////////////////////////////////////////////////////
	elapsedRKGParty += runTimedParty(func() {
		for _, pi := range P {
			rkg.GenShareRoundTwo(pi.rlkEphemSk, pi.sk, rkgCombined1, pi.rkgShareTwo)
		}
	}, len(P))

	rlk := ckks.NewRelinearizationKey(params)

	a = currentTotalAlloc()
	elapsedRKGCloud += runTimed(func() {
		for _, pi := range P {
			rkg.AggregateShare(pi.rkgShareTwo, rkgCombined2, rkgCombined2)
			// if err := Save("./multi_rkgCombined2_aggregated.tmp", rkgCombined2); err != nil {
			// 	log.Fatalln(err)
			// }
		}
		rkg.GenRelinearizationKey(rkgCombined1, rkgCombined2, rlk)
	})
	b = currentTotalAlloc()
	spTotalMemory += b - a

	return rlk
}

//geneate collective public key
func ckgphase(params ckks.Parameters, crs utils.PRNG, P []*party) *rlwe.PublicKey {

	ckg := dckks.NewCKGProtocol(params) // Public key generation
	ckgCombined := ckg.AllocateShare()
	for _, pi := range P {
		pi.ckgShare = ckg.AllocateShare()
	}
	// if err := Save("./multi_ckgCombined.tmp", ckgCombined); err != nil {
	// 	log.Fatalln(err)
	// }

	crp := ckg.SampleCRP(crs)
	elapsedCKGParty += runTimedParty(func() {
		for _, pi := range P {
			ckg.GenShare(pi.sk, crp, pi.ckgShare)
		}
	}, len(P))

	pk := ckks.NewPublicKey(params)

	a = currentTotalAlloc()
	elapsedCKGCloud += runTimed(func() {
		for _, pi := range P {
			ckg.AggregateShare(pi.ckgShare, ckgCombined, ckgCombined)
			// if i == 0 {
			// 	if err := Save("./multi_ckgCombined_aggregated.tmp", ckgCombined); err != nil {
			// 		log.Fatalln(err)
			// 	}
			// }
		}
		ckg.GenPublicKey(ckgCombined, crp, pk)
	})
	b = currentTotalAlloc()
	//record memory for public key(cloud)
	spTotalMemory += b - a

	return pk
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
	fmt.Printf("==============\n")
	fmt.Printf("\tspTotalMemory = %v MiB\n", spTotalMemory)
}

func currentTotalAlloc() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return bToMb(m.TotalAlloc)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}
