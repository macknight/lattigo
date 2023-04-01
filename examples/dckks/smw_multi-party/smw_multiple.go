package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/dckks"
	"github.com/tuneinsight/lattigo/v3/drlwe"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"
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

var elapsedAddition time.Duration
var elapsedMultiplication time.Duration
var elapsedRotation time.Duration

var elapsedSummation time.Duration
var elapsedDeviation time.Duration
var elapsedAnalystSummation time.Duration
var elapsedAnalystVariance time.Duration

var spTotalMemory uint64
var a uint64
var b uint64

var pathFormat = "C:\\Users\\23304161\\source\\smw\\%s\\House_10sec_1month_%d.csv"

// var pathFormat = "./%s/House_10sec_1month_%d.csv"

func main() {
	start := time.Now()

	loop := 1
	maximumLenPartyRows := 8640
	folderName := "200Houses_10s_1month_highVD"

	householdIDs := []int{}
	minHouseholdID := 1
	maxHouseholdID := 25

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

	// For more details about the PSI example see
	//     Multiparty Homomorphic Encryption: From Theory to Practice (<https://eprint.iacr.org/2020/304>)
	l := log.New(os.Stderr, "", 0)

	// $go run main.go arg1 arg2
	// arg1: number of parties
	// arg2: number of Go routines
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
	globalPartyRows, expSummation, expAverage, expDeviation := genInputs(params, P, maximumLenPartyRows) //globalPartyRows rows

	// 1) Collective public key generation
	pk := ckgphase(params, crs, P)

	// 2) Collective relinearization key generation
	rlk := rkgphase(params, crs, P)
	// 3) Collective rotation key generation
	rotk := rtkgphase(params, crs, P)

	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotk})

	//generate ciphertexts
	encInputsAverage, encInputsNegative, encInputsSummation := encPhase(params, P, pk, encoder)

	encSummationOuts := make([]*ckks.Ciphertext, 0)
	// encAverageOuts := make([]*ckks.Ciphertext, 0)
	encDeviationOuts := make([]*ckks.Ciphertext, 0)

	anaTime1 := time.Now()
	// summation
	for _, encInputSummation := range encInputsSummation {
		elapsedSummation += runTimed(func() {
			elapsedRotation += runTimedParty(func() {
				evaluator.InnerSumLog(encInputSummation, 1, params.Slots(), encInputSummation)
			}, len(P))
		})

		encSummationOuts = append(encSummationOuts, pcksPhase(params, tpk, encInputSummation, P))
	}
	elapsedAnalystSummation += time.Since(anaTime1)

	anaTime2 := time.Now()
	// deviation
	for i, encInputAverage := range encInputsAverage {
		elapsedDeviation += runTimed(func() {
			evaluator.InnerSumLog(encInputAverage, 1, params.Slots(), encInputAverage)
			encInputAverage.Scale *= float64(globalPartyRows) //each element contains the

			// encAverageOuts = append(encAverageOuts, pcksPhase(params, tpk, encInputAverage, P)) // cpk -> tpk, key switching

			elapsedAddition += runTimedParty(func() {
				evaluator.Add(encInputsNegative[i], encInputAverage, encInputsNegative[i])
			}, len(P))
			elapsedMultiplication += runTimedParty(func() {
				evaluator.MulRelin(encInputsNegative[i], encInputsNegative[i], encInputsNegative[i])
			}, len(P))

			evaluator.InnerSumLog(encInputsNegative[i], 1, params.Slots(), encInputsNegative[i])
			encInputsNegative[i].Scale *= float64(globalPartyRows)
		})

		encDeviationOuts = append(encDeviationOuts, pcksPhase(params, tpk, encInputsNegative[i], P)) // cpk -> tpk
	}
	elapsedAnalystVariance += time.Since(anaTime2)

	// Decrypt & Check the result
	l.Println("> Decrypt & Result:>>>>>>>>>>>>>")
	decryptor := ckks.NewDecryptor(params, tsk)

	// ptres := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())
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

	fmt.Printf("\tDecrypt Time: done (party: %s)\n", elapsedDecParty)
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

	elapsedEncryptCloud += time.Duration(0)
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedEncryptCloud, elapsedEncryptParty)

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
		}, N)
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

//key switching phase
func pcksPhase(params ckks.Parameters, tpk *rlwe.PublicKey, encRes *ckks.Ciphertext, P []*party) (encOut *ckks.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	// Collective key switching from the collective secret key to
	// the target public key

	pcks := dckks.NewPCKSProtocol(params, 3.19)

	for _, pi := range P {
		pi.pcksShare = pcks.AllocateShare(params.MaxLevel())
	}

	l.Println("> PCKS Phase(key switching)")
	elapsedPCKSParty += runTimedParty(func() {
		for _, pi := range P {
			pcks.GenShare(pi.sk, tpk, encRes.Value[1], pi.pcksShare)
		}
	}, len(P))

	pcksCombined := pcks.AllocateShare(params.MaxLevel())
	encOut = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
	elapsedPCKSCloud += runTimed(func() {
		for _, pi := range P {
			pcks.AggregateShare(pi.pcksShare, pcksCombined, pcksCombined)
		}
		pcks.KeySwitch(encRes, pcksCombined, encOut)

	})
	l.Printf("\tpcksPhase done (cloud: %s, party: %s)\n", elapsedPCKSCloud, elapsedPCKSParty)

	return

}

//generate collective rotation key
func rtkgphase(params ckks.Parameters, crs utils.PRNG, P []*party) *rlwe.RotationKeySet {
	l := log.New(os.Stderr, "", 0)

	l.Println("> RTKG Phase(collective rotation key)")

	rtg := dckks.NewRotKGProtocol(params) // Rotation keys generation

	for _, pi := range P {
		pi.rtgShare = rtg.AllocateShare()
	}

	galEls := params.GaloisElementsForRowInnerSum()
	rotKeySet := ckks.NewRotationKeySet(params, galEls)

	for _, galEl := range galEls {

		rtgShareCombined := rtg.AllocateShare()

		crp := rtg.SampleCRP(crs)

		elapsedRTGParty += runTimedParty(func() {
			for _, pi := range P {
				rtg.GenShare(pi.sk, galEl, crp, pi.rtgShare)
			}
		}, len(P))

		elapsedRTGCloud += runTimed(func() {
			for _, pi := range P {
				rtg.AggregateShare(pi.rtgShare, rtgShareCombined, rtgShareCombined)
			}
			rtg.GenRotationKey(rtgShareCombined, crp, rotKeySet.Keys[galEl])
		})
	}
	l.Printf("\trtkgphase done (cloud: %s, party %s)\n", elapsedRTGCloud, elapsedRTGParty)

	return rotKeySet
}

//generate collective relinearization key
func rkgphase(params ckks.Parameters, crs utils.PRNG, P []*party) *rlwe.RelinearizationKey {
	l := log.New(os.Stderr, "", 0)

	l.Println("> RKG Phase(collective relinearization key)")

	rkg := dckks.NewRKGProtocol(params) // Relineariation key generation
	_, rkgCombined1, rkgCombined2 := rkg.AllocateShare()

	for _, pi := range P {
		pi.rlkEphemSk, pi.rkgShareOne, pi.rkgShareTwo = rkg.AllocateShare()
	}

	crp := rkg.SampleCRP(crs)

	elapsedRKGParty += runTimedParty(func() {
		for _, pi := range P {
			rkg.GenShareRoundOne(pi.sk, crp, pi.rlkEphemSk, pi.rkgShareOne)
		}
	}, len(P))

	elapsedRKGCloud += runTimed(func() {
		for _, pi := range P {
			rkg.AggregateShare(pi.rkgShareOne, rkgCombined1, rkgCombined1)
		}
	})

	elapsedRKGParty += runTimedParty(func() {
		for _, pi := range P {
			rkg.GenShareRoundTwo(pi.rlkEphemSk, pi.sk, rkgCombined1, pi.rkgShareTwo)
		}
	}, len(P))

	rlk := ckks.NewRelinearizationKey(params)
	elapsedRKGCloud += runTimed(func() {
		for _, pi := range P {
			rkg.AggregateShare(pi.rkgShareTwo, rkgCombined2, rkgCombined2)
		}
		rkg.GenRelinearizationKey(rkgCombined1, rkgCombined2, rlk)
	})

	l.Printf("\trkgphase done (cloud: %s, party: %s)\n", elapsedRKGCloud, elapsedRKGParty)

	return rlk
}

//geneate collective public key
func ckgphase(params ckks.Parameters, crs utils.PRNG, P []*party) *rlwe.PublicKey {

	l := log.New(os.Stderr, "", 0)

	l.Println("> CKG Phase(collective public key)")

	ckg := dckks.NewCKGProtocol(params) // Public key generation
	ckgCombined := ckg.AllocateShare()
	for _, pi := range P {
		pi.ckgShare = ckg.AllocateShare()
	}

	crp := ckg.SampleCRP(crs)

	elapsedCKGParty += runTimedParty(func() {
		for _, pi := range P {
			ckg.GenShare(pi.sk, crp, pi.ckgShare)
		}
	}, len(P))

	pk := ckks.NewPublicKey(params)

	elapsedCKGCloud += runTimed(func() {
		for _, pi := range P {
			ckg.AggregateShare(pi.ckgShare, ckgCombined, ckgCombined)
		}
		ckg.GenPublicKey(ckgCombined, crp, pk)
	})

	l.Printf("\tckgphase done (cloud: %s, party: %s)\n", elapsedCKGCloud, elapsedCKGParty)

	return pk
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
