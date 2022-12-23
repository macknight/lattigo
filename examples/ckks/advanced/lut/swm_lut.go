package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v3/ckks"
	ckksAdvanced "github.com/tuneinsight/lattigo/v3/ckks/advanced"
	"github.com/tuneinsight/lattigo/v3/dckks"
	"github.com/tuneinsight/lattigo/v3/drlwe"
	"github.com/tuneinsight/lattigo/v3/rgsw/lut"
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"
)

// This example showcases how lookup tables can complement the CKKS scheme to compute non-linear functions
// such as sign. The example starts by homomorphically decoding the CKKS ciphertext from the canonical embeding
// to the coefficient embeding. It then evaluates the Look-Up-Table (LUT) on each coefficient and repacks the
// outputs of each LUT in a single RLWE ciphertext. Finally, it homomorphically encodes the RLWE ciphertext back
// to the canonical embeding of the CKKS scheme.

// ==============================
// Functions to evaluate with LUT
// ==============================
func sign(x float64) (y float64) {
	if x > 0 {
		return 1
	} else if x < 0 {
		return -1
	} else {
		return 0
	}
}

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
	var start time.Time
	start = time.Now()
	// For more details about the PSI example see
	//     Multiparty Homomorphic Encryption: From Theory to Practice (<https://eprint.iacr.org/2020/304>)
	l := log.New(os.Stderr, "", 0)

	// $go run main.go arg1 arg2
	// arg1: number of parties
	// arg2: number of Go routines
	var err error
	// Creating encryption parameters from a default params with logN=14, logQP=438 with a plaintext modulus T=65537
	// paramsDef := ckks.PN14QP438CI //PN16QP1761CI
	paramsDef := ckks.ParametersLiteral{
		LogN:         18,
		LogQ:         []int{55, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40},
		LogP:         []int{45, 45},
		LogSlots:     18,
		RingType:     ring.ConjugateInvariant,
		DefaultScale: 1 << 45,
	}
	params, err := ckks.NewParametersFromLiteral(paramsDef)
	check(err)

	crs, err := utils.NewKeyedPRNG([]byte{'l', 'a', 't', 't', 'i', 'g', 'o'})
	check(err)
	encoder := ckks.NewEncoder(params)
	// Target private and public keys
	tkgen := ckks.NewKeyGenerator(params)
	tsk, tpk := tkgen.GenKeyPair()

	folderName := "200Houses_10s_1month_highNE"
	householdIDs := []int{1, 2, 3} // using suffix IDs of the csv files
	// Largest for n=8192: 512 parties

	// Create each party, and allocate the memory for all the shares that the protocols will need
	// create parties
	P := genparties(params, folderName, householdIDs)

	// Inputs & expected result, cleartext result
	//read CSV files, len(expRes) == size of rows
	// fulfill P's input property & fulfill expRes as comparison
	genInputs(params, P)

	// 1) Collective public key generation
	pk := ckgphase(params, crs, P)

	// 2) Collective relinearization key generation & rotation key generation
	rlk := rkgphase(params, crs, P)
	rotk := rtkgphase(params, crs, P)

	// 3) Create evaluator
	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotk})

	l.Printf("\tdone (cloud: %s, party: %s)\n",
		elapsedRKGCloud, elapsedRKGParty)
	l.Printf("\tSetup done (cloud: %s, party: %s)\n",
		elapsedRKGCloud+elapsedCKGCloud, elapsedRKGParty+elapsedCKGParty)

	//generate ciphertexts
	//encInputs is positive
	//encInputsCopy is negative
	encInputs, _ := encPhase(params, P, pk, encoder)
	encOuts := make([]*ckks.Ciphertext, 0) // here length should be 0, otherwise append will not right.
	// delete encRes
	// calcuate the sum of each encInput
	for _, encInput := range encInputs {
		evaluator.InnerSumLog(encInput, 1, params.Slots(), encInput)   // add sum
		encOuts = append(encOuts, pcksPhase(params, tpk, encInput, P)) //switch-key and include to encOuts
	}

	// Decrypt & Check the result
	l.Println("> Decrypt & Result:")
	decryptor := ckks.NewDecryptor(params, tsk) // decrypt using the target secret key
	ptres := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())
	for i, encOut := range encOuts {
		elapsedDecParty += runTimed(func() {
			decryptor.Decrypt(encOut, ptres) //ciphertext->plaintext
		})
		res := encoder.Decode(ptres, params.LogSlots())
		calculatedSum := real(res[0])
		fmt.Printf("> Calculated Sum of elements of encOuts[%d]: %.6f", i, calculatedSum)
		expSum := float64(0)
		for _, element := range P[i].input {
			expSum += element
		}
		fmt.Printf("> Expected Sum of elements of encOuts[%d]: %.6f", i, expSum)
	}

	l.Printf("\tdone (party: %s)\n", elapsedDecParty)

	//elapsedDuration
	fmt.Printf("> Finished (total cloud: %s, total party: %s)\n",
		elapsedCKGCloud+elapsedRKGCloud+elapsedRTGCloud+elapsedEncryptCloud+elapsedEvalCloud+elapsedPCKSCloud,
		elapsedCKGParty+elapsedRKGParty+elapsedRTGParty+elapsedEncryptParty+elapsedEvalParty+elapsedPCKSParty+elapsedDecParty)
	fmt.Println()

	fmt.Printf("Main() Done in %s \n", time.Since(start))
}

//main end

// encPhase to get []ciphertext
func encPhase(params ckks.Parameters, P []*party, pk *rlwe.PublicKey, encoder ckks.Encoder) (encInputs, encInputsCopy []*ckks.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	encInputs = make([]*ckks.Ciphertext, len(P))
	encInputsCopy = make([]*ckks.Ciphertext, len(P))
	for i := range encInputs {
		encInputs[i] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
		encInputsCopy[i] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
	}

	// Each party encrypts its input vector
	l.Println("> Encrypt Phase")
	encryptor := ckks.NewEncryptor(params, pk)

	pt := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())
	elapsedEncryptParty = runTimedParty(func() {
		for i, pi := range P {
			encoder.Encode(pi.input, pt, params.LogSlots())
			encryptor.Encrypt(pt, encInputs[i])
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
	}, len(P))

	elapsedEncryptCloud = time.Duration(0)
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedEncryptCloud, elapsedEncryptParty)

	return
}

//evaluator phase between parties
func evalPhase(params ckks.Parameters, NGoRoutine int, encInputs []*ckks.Ciphertext, evaluator ckks.Evaluator) (encRes *ckks.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	encLvls := make([][]*ckks.Ciphertext, 0)
	encLvls = append(encLvls, encInputs)
	for nLvl := len(encInputs) / 2; nLvl > 0; nLvl = nLvl >> 1 {
		encLvl := make([]*ckks.Ciphertext, nLvl)
		for i := range encLvl {
			encLvl[i] = ckks.NewCiphertext(params, 2, params.MaxLevel(), params.DefaultScale())
		}
		encLvls = append(encLvls, encLvl)
	}
	encRes = encLvls[len(encLvls)-1][0]

	// Split the task among the Go routines
	tasks := make(chan *task)
	workers := &sync.WaitGroup{}
	workers.Add(NGoRoutine)
	//l.Println("> Spawning", NGoRoutine, "evaluator goroutine")
	//对数据进行处理的handler
	for i := 1; i <= NGoRoutine; i++ {
		go func(i int) {
			evaluator := evaluator.ShallowCopy() // creates a shallow evaluator copy for this goroutine
			for task := range tasks {
				task.elapsedtask = runTimed(func() {
					// 1) Addition of two input vectors
					evaluator.Add(task.op1, task.op2, task.res)
				})
				task.wg.Done()
			}
			//l.Println("\t evaluator", i, "down")
			workers.Done()
		}(i)
		//l.Println("\t evaluator", i, "started")
	}

	// Start the tasks, 塞数据
	taskList := make([]*task, 0)
	l.Println("> Eval Phase")
	elapsedEvalCloud = runTimed(func() {
		for i, lvl := range encLvls[:len(encLvls)-1] {
			nextLvl := encLvls[i+1]
			l.Println("\tlevel", i, len(lvl), "->", len(nextLvl))
			wg := &sync.WaitGroup{}
			wg.Add(len(nextLvl))
			for j, nextLvlCt := range nextLvl {
				task := task{wg, lvl[2*j], lvl[2*j+1], nextLvlCt, 0}
				taskList = append(taskList, &task)
				tasks <- &task
			}
			wg.Wait()
		}
	})
	elapsedEvalCloudCPU = time.Duration(0)
	for _, t := range taskList {
		elapsedEvalCloudCPU += t.elapsedtask
	}
	elapsedEvalParty = time.Duration(0)
	l.Printf("\tdone (cloud: %s (wall: %s), party: %s)\n",
		elapsedEvalCloudCPU, elapsedEvalCloud, elapsedEvalParty)

	//l.Println("> Shutting down workers")
	close(tasks)
	workers.Wait()

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
func genInputs(params ckks.Parameters, P []*party) (expRes []float64) {

	globalPartyRows := -1
	for _, pi := range P {
		partyRows := resizeCSV(pi.folderName, pi.id)
		lenPartyRows := len(partyRows)

		if globalPartyRows == -1 {
			//global setting, run once
			globalPartyRows = lenPartyRows
			expRes = make([]float64, globalPartyRows)
		} else if globalPartyRows != lenPartyRows {
			//make sure pi.input[] has the same size
			err := errors.New("Not all files have the same rows")
			check(err)
		}

		pi.input = make([]float64, lenPartyRows)
		for i := range pi.input {
			pi.input[i] = partyRows[i]
			expRes[i] += pi.input[i]
		}

	}

	//average by P parties
	for i, _ := range expRes {
		expRes[i] /= float64(len(P))
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
	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedPCKSCloud, elapsedPCKSParty)

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
	l.Printf("\tdone (cloud: %s, party %s)\n", elapsedRTGCloud, elapsedRTGParty)

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

	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedRKGCloud, elapsedRKGParty)

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

	l.Printf("\tdone (cloud: %s, party: %s)\n", elapsedCKGCloud, elapsedCKGParty)

	return pk
}

func test_lut() {

	var err error

	// Base ring degree
	LogN := 12

	// Q modulus Q
	Q := []uint64{0x800004001, 0x40002001} // 65.0000116961637 bits

	// P modulus P
	P := []uint64{0x4000026001} // 38.00000081692261 bits

	flagShort := flag.Bool("short", false, "runs the example with insecure parameters for fast testing")
	flag.Parse()

	if *flagShort {
		LogN = 6
	}

	// Starting RLWE params, size of these params
	// determine the complexity of the LUT:
	// each LUT takes N RGSW ciphertext-ciphetext mul.
	// LogN = 12 & LogQP = ~103 -> >128-bit secure.
	var paramsN12 ckks.Parameters
	if paramsN12, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN: LogN, //logN=12 => N=4096
		Q:    Q,    //Q := []uint64{0x800004001, 0x40002001}
		P:    P,    //P := []uint64{0x4000026001}
		//then Q*P =>	34359754753*1073750017*274878062593=10141292761039441820029989076993
		LogSlots:     4,
		DefaultScale: 1 << 32,
	}); err != nil {
		panic(err)
	}

	// Params for Key-switching N12 to N11.
	// LogN = 12 & LogQP = ~54 -> >>>128-bit secure.
	var paramsN12ToN11 ckks.Parameters
	if paramsN12ToN11, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:     LogN,  //12
		Q:        Q[:1], //[]uint64{0x800004001}
		P:        []uint64{0x42001},
		Pow2Base: 16,
	}); err != nil {
		panic(err)
	}

	// LUT RLWE params, N of these params determine
	// the LUT poly and therefore precision.
	// LogN = 11 & LogQP = ~54 -> 128-bit secure.
	var paramsN11 ckks.Parameters
	if paramsN11, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:     LogN - 1, //11
		Q:        Q[:1],    //[]uint64{0x800004001}
		P:        []uint64{0x42001},
		Pow2Base: 12,
	}); err != nil {
		panic(err)
	}

	// LUT interval
	a, b := -8.0, 8.0

	// Rescale inputs during Homomorphic Decoding by the normalization of the
	// LUT inputs and change of scale to ensure that upperbound on the homomorphic
	// decryption of LWE during the LUT evaluation X^{dec(lwe)} is smaller than N
	// to avoid negacyclic wrapping of X^{dec(lwe)}.
	diffScale := paramsN11.QiFloat64(0) / (4.0 * paramsN12.DefaultScale()) //1 << 34

	fmt.Printf("diffScale=%7.4f\n", diffScale) //2.0

	normalization := 2.0 / (b - a) // all inputs are normalized before the LUT evaluation. 0.125

	fmt.Printf("normalization=%7.4f\n", normalization) //0.125

	//normalization * diffScale => 0.25 => 1/4
	fmt.Printf("normalization * diffScale=%7.4f\n", normalization*diffScale) //0.25 => 1/4

	// SlotsToCoeffsParameters homomorphic encoding parameters
	var SlotsToCoeffsParameters = ckksAdvanced.EncodingMatrixLiteral{
		LogN:                paramsN12.LogN(),          //12
		LogSlots:            paramsN12.LogSlots(),      //4, 2^4=16
		Scaling:             normalization * diffScale, //0.25
		LinearTransformType: ckksAdvanced.SlotsToCoeffs,
		RepackImag2Real:     false,
		LevelStart:          1,     // starting level
		BSGSRatio:           4.0,   // ratio between n1/n2 for n1*n2 = slots
		BitReversed:         false, // bit-reversed input
		ScalingFactor: [][]float64{ // Decomposition level of the encoding matrix
			{paramsN12.QiFloat64(1)}, // Scale of the decoding matrix
		},
	}

	// CoeffsToSlotsParameters homomorphic decoding parameters
	var CoeffsToSlotsParameters = ckksAdvanced.EncodingMatrixLiteral{
		LogN:                paramsN12.LogN(),               //12
		LogSlots:            paramsN12.LogSlots(),           //4, 2^4=16
		Scaling:             1 / float64(paramsN12.Slots()), //1/16 = 0.0625
		LinearTransformType: ckksAdvanced.CoeffsToSlots,
		RepackImag2Real:     false,
		LevelStart:          1,     // starting level
		BSGSRatio:           4.0,   // ratio between n1/n2 for n1*n2 = slots
		BitReversed:         false, // bit-reversed input
		ScalingFactor: [][]float64{ // Decomposition level of the encoding matrix
			{paramsN12.QiFloat64(1)}, // Scale of the encoding matrix
		},
	}

	fmt.Printf("Generating LUT... ")
	now := time.Now()
	// Generate LUT, provide function, outputscale, ring and interval.
	LUTPoly := lut.InitLUT(sign, paramsN12.DefaultScale(), paramsN12.RingQ(), a, b) //look up table
	fmt.Printf("Done (%s)\n", time.Since(now))

	// Index of the LUT poly and repacking after evaluating the LUT.
	lutPolyMap := make(map[int]*ring.Poly)            // Which slot to evaluate on the LUT
	repackIndex := make(map[int]int)                  // Where to repack slots after the LUT
	gapN11 := paramsN11.N() / (2 * paramsN12.Slots()) //2^11 / 2^5 = 2^6 = 64
	gapN12 := paramsN12.N() / (2 * paramsN12.Slots()) //2^12 / 2^5 = 2^7 = 128

	for i := 0; i < paramsN12.Slots(); i++ { //i = 0; i<16; i++
		lutPolyMap[i*gapN11] = LUTPoly     //[0, 64, 128,..., 960] = LUTPoly
		repackIndex[i*gapN11] = i * gapN12 //[0, 64, 128,..., 960] = 0, 128,..., 1920
	}

	kgenN12 := ckks.NewKeyGenerator(paramsN12)
	skN12 := kgenN12.GenSecretKey()
	encoderN12 := ckks.NewEncoder(paramsN12)
	encryptorN12 := ckks.NewEncryptor(paramsN12, skN12)
	decryptorN12 := ckks.NewDecryptor(paramsN12, skN12)

	kgenN11 := ckks.NewKeyGenerator(paramsN11)
	skN11 := kgenN11.GenSecretKey()
	//decryptorN11 := ckks.NewDecryptor(paramsN11, skN11)
	//encoderN11 := ckks.NewEncoder(paramsN11)

	// Switchingkey RLWEN12 -> RLWEN11
	swkN12ToN11 := ckks.NewKeyGenerator(paramsN12ToN11).GenSwitchingKey(skN12, skN11)

	fmt.Printf("Gen SlotsToCoeffs Matrices... ")
	now = time.Now()
	SlotsToCoeffsMatrix := ckksAdvanced.NewHomomorphicEncodingMatrixFromLiteral(SlotsToCoeffsParameters, encoderN12)
	CoeffsToSlotsMatrix := ckksAdvanced.NewHomomorphicEncodingMatrixFromLiteral(CoeffsToSlotsParameters, encoderN12)
	fmt.Printf("Done (%s)\n", time.Since(now))

	// Rotation Keys
	rotations := []int{}
	for i := 1; i < paramsN12.N(); i <<= 1 { //i=1;i<4096;i=2*i  => add 1,2,4,8,2048;total 12 iterations
		rotations = append(rotations, i)
	}

	rotations = append(rotations, SlotsToCoeffsParameters.Rotations()...)
	rotations = append(rotations, CoeffsToSlotsParameters.Rotations()...)

	rotKey := kgenN12.GenRotationKeysForRotations(rotations, true, skN12)

	// LUT Evaluator
	evalLUT := lut.NewEvaluator(paramsN12.Parameters, paramsN11.Parameters, rotKey)

	// CKKS Evaluator
	evalCKKS := ckksAdvanced.NewEvaluator(paramsN12, rlwe.EvaluationKey{Rlk: nil, Rtks: rotKey})
	evalCKKSN12ToN11 := ckks.NewEvaluator(paramsN12ToN11, rlwe.EvaluationKey{})

	fmt.Printf("Encrypting bits of skLWE in RGSW... ")
	now = time.Now()
	LUTKEY := lut.GenEvaluationKey(paramsN12.Parameters, skN12, paramsN11.Parameters, skN11) // Generate RGSW(sk_i) for all coefficients of sk
	fmt.Printf("Done (%s)\n", time.Since(now))

	// Generates the starting plaintext values.
	interval := (b - a) / float64(paramsN12.Slots()) // 16/16 = 1
	values := make([]float64, paramsN12.Slots())     // [16] float64
	for i := 0; i < paramsN12.Slots(); i++ {
		values[i] = a + float64(i)*interval
		// fmt.Printf("Value[%d]=%7.4f\n", i, values[i])
		//Value[0]=-8.0000;Value[1]=-7.0000;Value[2]=-6.0000;Value[3]=-5.0000;Value[4]=-4.0000;Value[5]=-3.0000;Value[6]=-2.0000;Value[7]=-1.0000;Value[8]= 0.0000;Value[9]= 1.0000;Value[10]= 2.0000;Value[11]= 3.0000;Value[12]= 4.0000;Value[13]= 5.0000;Value[14]= 6.0000;Value[15]= 7.0000
	}

	pt := ckks.NewPlaintext(paramsN12, paramsN12.MaxLevel(), paramsN12.DefaultScale())
	encoderN12.EncodeSlots(values, pt, paramsN12.LogSlots()) //encode
	ctN12 := encryptorN12.EncryptNew(pt)                     //encrypt values[] into ctN12

	fmt.Printf("Homomorphic Decoding... ")
	now = time.Now()
	// Homomorphic Decoding: [(a+bi), (c+di)] -> [a, c, b, d]
	ctN12 = evalCKKS.SlotsToCoeffsNew(ctN12, nil, SlotsToCoeffsMatrix)
	ctN12.Scale = paramsN11.QiFloat64(0) / 4.0

	// Key-Switch from LogN = 12 to LogN = 10
	evalCKKS.DropLevel(ctN12, ctN12.Level())                    // drop to LUT level
	ctTmp := evalCKKSN12ToN11.SwitchKeysNew(ctN12, swkN12ToN11) // key-switch to LWE degree
	ctN11 := ckks.NewCiphertext(paramsN11, 1, paramsN11.MaxLevel(), ctTmp.Scale)
	// prepare ctN11 by ctTmp
	rlwe.SwitchCiphertextRingDegreeNTT(ctTmp.Ciphertext, paramsN11.RingQ(), paramsN12.RingQ(), ctN11.Ciphertext)
	fmt.Printf("Done (%s)\n", time.Since(now))

	//for i, v := range encoderN11.DecodeCoeffs(decryptorN11.DecryptNew(ctN11)){
	//	fmt.Printf("%3d: %7.4f\n", i, v)
	//}

	fmt.Printf("Evaluating LUT... ")
	now = time.Now()
	// Extracts & EvalLUT(LWEs, indexLUT) on the fly -> Repack(LWEs, indexRepack) -> RLWE
	ctN12.Ciphertext = evalLUT.EvaluateAndRepack(ctN11.Ciphertext, lutPolyMap, repackIndex, LUTKEY)
	ctN12.Scale = paramsN12.DefaultScale()
	fmt.Printf("Done (%s)\n", time.Since(now))

	// for i, v := range encoderN12.DecodeCoeffs(decryptorN12.DecryptNew(ctN12)) {
	// 	fmt.Printf("%3d: %7.4f\n", i, v)
	// }

	fmt.Printf("Homomorphic Encoding... ")
	now = time.Now()
	// Homomorphic Encoding: [LUT(a), LUT(c), LUT(b), LUT(d)] -> [(LUT(a)+LUT(b)i), (LUT(c)+LUT(d)i)]
	ctN12, _ = evalCKKS.CoeffsToSlotsNew(ctN12, CoeffsToSlotsMatrix)
	fmt.Printf("Done (%s)\n", time.Since(now))

	for i, v := range encoderN12.Decode(decryptorN12.DecryptNew(ctN12), paramsN12.LogSlots()) {
		fmt.Printf("%7.4f -> %7.4f\n", values[i], v)
	}
}
