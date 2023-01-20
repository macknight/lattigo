package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"os"
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
var elapsedRKGCloud time.Duration
var elapsedRKGParty time.Duration
var elapsedRTGCloud time.Duration
var elapsedRTGParty time.Duration
var elapsedPCKSCloud time.Duration
var elapsedPCKSParty time.Duration
var elapsedEvalCloudCPU time.Duration
var elapsedEvalCloud time.Duration
var elapsedEvalParty time.Duration
var elapsedDecParty time.Duration
var pathFormat = "C:\\Users\\23304161\\source\\smw\\%s\\House_10sec_1month_%d.csv"

//main start
func main() {
	start := time.Now()
	// For more details about the PSI example see
	//     Multiparty Homomorphic Encryption: From Theory to Practice (<https://eprint.iacr.org/2020/304>)
	l := log.New(os.Stderr, "", 0)

	// $go run main.go arg1 arg2
	// arg1: number of parties
	// arg2: number of Go routines
	var err error
	// Creating encryption parameters from a default params with logN=14, logQP=438 with a plaintext modulus T=65537
	paramsDef := ckks.PN14QP438CI
	params, err := ckks.NewParametersFromLiteral(paramsDef)
	check(err)
	folderName := "200Houses_10s_1month_highNE"
	householdIDs := []int{6} // using suffix IDs of the csv files
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
	globalPartyRows, expAverage, expDeviation := genInputs(params, P) //globalPartyRows rows

	// 1) Collective public key generation
	pk := ckgphase(params, crs, P)

	// 2) Collective relinearization key generation
	rlk := rkgphase(params, crs, P)
	// 3) Collective rotation key generation
	rotk := rtkgphase(params, crs, P)

	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotk})

	//generate ciphertexts
	//encInputsCopy2 for summation
	//encInputs, encInputsCopy for deviation
	encInputs, encInputsCopy, encInputsCopy2 := encPhase(params, P, pk, encoder)

	encOuts := make([]*ckks.Ciphertext, 0)
	encDeviationOuts := make([]*ckks.Ciphertext, 0)

	// deviation
	for i, encInput := range encInputs {
		evaluator.InnerSumLog(encInput, 1, params.Slots(), encInput)
		encInput.Scale *= float64(globalPartyRows) //each element contains the

		encOuts = append(encOuts, pcksPhase(params, tpk, encInput, P)) // cpk -> tpk, key switching

		evaluator.Add(encInputsCopy[i], encInput, encInputsCopy[i])
		evaluator.MulRelin(encInputsCopy[i], encInputsCopy[i], encInputsCopy[i])

		evaluator.InnerSumLog(encInputsCopy[i], 1, params.Slots(), encInputsCopy[i])
		encInputsCopy[i].Scale *= float64(globalPartyRows)

		encDeviationOuts = append(encDeviationOuts, pcksPhase(params, tpk, encInputsCopy[i], P)) // cpk -> tpk
	}

	// Decrypt & Check the result
	l.Println("> Decrypt & Result:>>>>>>>>>>>>>")

	decryptor := ckks.NewDecryptor(params, tsk) // decrypt using the target secret key
	ptres := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())
	ptresDeviation := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())
	ptresSummation := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())

	// summation
	for i, encInputCopy2 := range encInputsCopy2 {
		evaluator.InnerSumLog(encInputCopy2, 1, params.Slots(), encInputCopy2)
		encSummationOut := pcksPhase(params, tpk, encInputCopy2, P) //*若无此行，则结果错误
		elapsedDecParty += runTimed(func() {
			decryptor.Decrypt(encSummationOut, ptresSummation) //ciphertext->plaintext
		})
		resSummation := encoder.Decode(ptresSummation, params.LogSlots()) //plaintext->complex numbers
		fmt.Printf("CKKS Summation of Party[%d]=%.6f\t", i, real(resSummation[0]))
		fmt.Println()
	}

	// deviation
	for i, _ := range encOuts {
		elapsedDecParty += runTimed(func() {
			decryptor.Decrypt(encOuts[i], ptres)                   //ciphertext->plaintext
			decryptor.Decrypt(encDeviationOuts[i], ptresDeviation) //ciphertext->plaintext
		})

		res := encoder.Decode(ptres, params.LogSlots())
		resDeviation := encoder.Decode(ptresDeviation, params.LogSlots())

		calculatedAverage := real(res[0])

		fmt.Printf("CKKS Average of Party[%d]=%.6f\t", i, calculatedAverage)
		fmt.Printf(" <===> Expected Average of Party[%d]=%.6f\t", i, expAverage[i])
		fmt.Println()

		//extra value for deviation
		delta := calculatedAverage * calculatedAverage * float64(len(resDeviation)-globalPartyRows) / float64(globalPartyRows)

		fmt.Printf("CKKS Deviation of Party[%d]=%.6f\t", i, real(resDeviation[0])-delta)
		fmt.Printf(" <===> Expected Deviation of Party[%d]=%.6f\t", i, expDeviation[i])
		fmt.Println()
	}

	l.Printf("\tDecrypt Time: done (party: %s)\n", time.Duration(elapsedDecParty.Nanoseconds()/int64(3*len(encInputsCopy2))))

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

	//elapsedDuration
	fmt.Printf("> Finished (total cloud: %s, total party: %s)\n",
		elapsedCKGCloud+elapsedRKGCloud+elapsedRTGCloud+elapsedEncryptCloud+elapsedEvalCloud+elapsedPCKSCloud,
		elapsedCKGParty+elapsedRKGParty+elapsedRTGParty+elapsedEncryptParty+elapsedEvalParty+elapsedPCKSParty+elapsedDecParty)
	fmt.Println()

	fmt.Printf("Main() Done in %s \n", time.Since(start))
}

//main end

// encPhase to get []ciphertext
func encPhase(params ckks.Parameters, P []*party, pk *rlwe.PublicKey, encoder ckks.Encoder) (encInputs, encInputsCopy, encInputsCopy2 []*ckks.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	encInputs = make([]*ckks.Ciphertext, len(P))
	encInputsCopy = make([]*ckks.Ciphertext, len(P))
	encInputsCopy2 = make([]*ckks.Ciphertext, len(P))

	for i := range encInputs {
		encInputs[i] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
		encInputsCopy[i] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
		encInputsCopy2[i] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
	}

	// Each party encrypts its input vector
	l.Println("> Encrypt Phase<<<<<<<<<<<<<<<<<<")
	encryptor := ckks.NewEncryptor(params, pk)
	pt := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())

	elapsedEncryptParty = runTimedParty(func() {
		for i, pi := range P {
			encoder.Encode(pi.input, pt, params.LogSlots())
			encryptor.Encrypt(pt, encInputs[i])
			encryptor.Encrypt(pt, encInputsCopy2[i])
			//turn pi.input to negative
			for j, _ := range pi.input {
				pi.input[j] *= -1
			}
			encoder.Encode(pi.input, pt, params.LogSlots())
			encryptor.Encrypt(pt, encInputsCopy[i])
			////turn pi.input to positive
			for j, _ := range pi.input {
				pi.input[j] *= -1
			}
		}
	}, 3*len(P)) //3 encryption in function

	elapsedEncryptCloud = time.Duration(0)
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
		pi.sk = ckks.NewKeyGenerator(params).GenSecretKey()
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
func genInputs(params ckks.Parameters, P []*party) (globalPartyRows int, expAverage, expDeviation []float64) {

	globalPartyRows = -1
	for pi, po := range P {
		partyRows := resizeCSV(po.folderName, po.id)
		lenPartyRows := len(partyRows)

		if globalPartyRows == -1 {
			//global setting, run once
			globalPartyRows = lenPartyRows
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
			expAverage[pi] += po.input[i]
		}

		expAverage[pi] /= float64(globalPartyRows)

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
	elapsedPCKSParty = runTimedParty(func() {
		for _, pi := range P {
			pcks.GenShare(pi.sk, tpk, encRes.Value[1], pi.pcksShare)
		}
	}, len(P))

	pcksCombined := pcks.AllocateShare(params.MaxLevel())
	encOut = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
	elapsedPCKSCloud = runTimed(func() {
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
	fmt.Println("galEls size:", len(galEls))
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

	elapsedRKGParty = runTimedParty(func() {
		for _, pi := range P {
			rkg.GenShareRoundOne(pi.sk, crp, pi.rlkEphemSk, pi.rkgShareOne)
		}
	}, len(P))

	elapsedRKGCloud = runTimed(func() {
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

	elapsedCKGParty = runTimedParty(func() {
		for _, pi := range P {
			ckg.GenShare(pi.sk, crp, pi.ckgShare)
		}
	}, len(P))

	pk := ckks.NewPublicKey(params)

	elapsedCKGCloud = runTimed(func() {
		for _, pi := range P {
			ckg.AggregateShare(pi.ckgShare, ckgCombined, ckgCombined)
		}
		ckg.GenPublicKey(ckgCombined, crp, pk)
	})

	l.Printf("\tckgphase done (cloud: %s, party: %s)\n", elapsedCKGCloud, elapsedCKGParty)

	return pk
}
