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
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"
)

// Check the result
const float64EqualityThreshold = 1e-4

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
	id         int
	folderName string
	sk         *rlwe.SecretKey
	rlkEphemSk *rlwe.SecretKey
	//ckgphase
	ckgShare *drlwe.CKGShare
	//rkgphase
	rkgShareOne *drlwe.RKGShare
	rkgShareTwo *drlwe.RKGShare
	//rtgphase
	rtgShare *drlwe.RTGShare
	//pcksphase
	pcksShare *drlwe.PCKSShare

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
var pathFormat = "C:\\Users\\23304161\\source\\smw\\%s\\House_10sec_1month_%d.csv"

//main start
func main() {
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
	tsk, tpk := ckks.NewKeyGenerator(params).GenKeyPair()

	NGoRoutine := 1 // Default number of Go routines

	folderName := "200Houses_10s_1month_highNE"
	householdIDs := []int{1, 2, 3}
	// Largest for n=8192: 512 parties
	// N := 5 // Default number of parties

	// Create each party, and allocate the memory for all the shares that the protocols will need
	P := genparties(params, folderName, householdIDs)

	// Inputs & expected result, cleartext result
	expRes := genInputs(params, P) //read CSV files, len(expRes) == size of rows

	// 1) Collective public key generation
	pk := ckgphase(params, crs, P)

	// 2) Collective relinearization key generation
	rlk := rkgphase(params, crs, P)
	rotk := rtgphase(params, crs, P)

	evaluator := ckks.NewEvaluator(params, rlwe.EvaluationKey{Rlk: rlk, Rtks: rotk})

	l.Printf("\tdone (cloud: %s, party: %s)\n",
		elapsedRKGCloud, elapsedRKGParty)
	l.Printf("\tSetup done (cloud: %s, party: %s)\n",
		elapsedRKGCloud+elapsedCKGCloud, elapsedRKGParty+elapsedCKGParty)

	//generate ciphertexts
	encInputs := encPhase(params, P, pk, encoder)
	fmt.Println("level[]:")
	for _, encInput := range encInputs {
		fmt.Println("level:", encInput.Level())
	}
	var tmpEncInputs []*ckks.Ciphertext
	var encRes *ckks.Ciphertext
	var sumGroupSize int
	var lenEncInputs int //8 people
	//encInputs groups
	for len(encInputs) > 1 {
		lenEncInputs = len(encInputs)
		binaryStr := strconv.FormatInt(int64(lenEncInputs), 2) //1000
		lenBinaryStr := len(binaryStr)                         //4
		tmpEncInputs = make([]*ckks.Ciphertext, 0)
		sumGroupSize = 0
		for i := 0; i < lenBinaryStr; i++ {
			if binaryStr[i] == 49 { // '1'
				groupSize := int(math.Pow(2, float64(lenBinaryStr-i-1)))
				//multiple ciphertexts->one ciphertext
				tmpEncInputs = append(tmpEncInputs, evalPhase(params, NGoRoutine, encInputs[sumGroupSize:sumGroupSize+groupSize], evaluator))
				sumGroupSize += groupSize
			}
		}
		encInputs = tmpEncInputs
	}
	encRes = encInputs[0]
	fmt.Println("level encRes:", encRes.Level())

	//calcuate the average of encRes
	evaluator.InnerSumLog(encRes, 1, len(expRes), encRes)
	encRes.Scale *= float64(len(expRes))

	//key switching!!!
	//ciphertext->ciphertext, key switching to the target key pair tpk/tsk for further usage
	encOut := pcksPhase(params, tpk, encRes, P) // ckks.ciphertext
	encOut.Scale *= float64(len(P))
	fmt.Println("level encOut:", encOut.Level())

	// Decrypt the result with the target secret key
	l.Println("> Result:")
	decryptor := ckks.NewDecryptor(params, tsk) // decrypt using the target secret key
	ptres := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())
	elapsedDecParty := runTimed(func() {
		decryptor.Decrypt(encOut, ptres) //ciphertext->plaintext
	})

	// Check the result
	res := encoder.Decode(ptres, params.LogSlots())
	//print result
	visibleNum := 3

	fmt.Println("> Parties:")
	//different parties
	for i, pi := range P {
		fmt.Printf("Party %3d(%d):\t\t", i, len(pi.input))
		for j, element := range pi.input {
			if j < visibleNum || (j > len(expRes)-visibleNum && j < len(expRes)) {
				fmt.Printf("[%d]%.6f\t", j, element)
			}
		}
		fmt.Println()
	}

	fmt.Printf("> CKKS Average of parties:\t\t")
	for i, r := range res {
		if i < visibleNum || (i > len(expRes)-visibleNum && i < len(expRes)) {
			fmt.Printf("encOut[%d]%.6f\t", i, real(r))
		}
	}
	fmt.Println()

	expSum := float64(0)
	for _, expRe := range expRes {
		expSum += expRe
	}
	fmt.Printf("> Expected Average of elements of encOut: %.6f", expSum/float64(len(expRes)))
	fmt.Println()

	decryptedResult := encoder.Decode(decryptor.DecryptNew(encOut), params.LogSlots())
	fmt.Printf("> CKKS Average of encOut: %f", real(decryptedResult[0]))

	fmt.Printf("> Finished (total cloud: %s, total party: %s)\n",
		elapsedCKGCloud+elapsedRKGCloud+elapsedEncryptCloud+elapsedEvalCloud+elapsedPCKSCloud,
		elapsedCKGParty+elapsedRKGParty+elapsedEncryptParty+elapsedEvalParty+elapsedPCKSParty+elapsedDecParty)
	fmt.Println()
}

//main end

// encPhase to get []ciphertext
func encPhase(params ckks.Parameters, P []*party, pk *rlwe.PublicKey, encoder ckks.Encoder) (encInputs []*ckks.Ciphertext) {

	l := log.New(os.Stderr, "", 0)

	encInputs = make([]*ckks.Ciphertext, len(P))
	for i := range encInputs {
		encInputs[i] = ckks.NewCiphertext(params, 1, params.MaxLevel(), params.DefaultScale())
	}

	// Each party encrypts its input vector
	l.Println("> Encrypt Phase")
	encryptor := ckks.NewEncryptor(params, pk)

	pt := ckks.NewPlaintext(params, params.MaxLevel(), params.DefaultScale())
	elapsedEncryptParty = runTimedParty(func() {
		for i, pi := range P {
			encoder.Encode(pi.input, pt, params.LogSlots())
			encryptor.Encrypt(pt, encInputs[i])
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
			//global setting
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

	l.Println("> PCKS Phase")
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
func rtgphase(params ckks.Parameters, crs utils.PRNG, P []*party) *rlwe.RotationKeySet {
	l := log.New(os.Stderr, "", 0)

	l.Println("> RTG Phase")

	rtg := dckks.NewRotKGProtocol(params) // Rotation key generation
	rtgCombined := rtg.AllocateShare()

	for _, pi := range P {
		pi.rtgShare = rtg.AllocateShare()
	}

	crp := rtg.SampleCRP(crs)
	//get rotations
	ks := params.RotationsForInnerSumLog(1, len(P[0].input))
	//get galEls from rotations, refer to "GenRotationKeysForRotations"
	//not includeConjugate
	galEls := make([]uint64, len(ks), len(ks)+1)
	for i, k := range ks {
		galEls[i] = params.GaloisElementForColumnRotationBy(k)
	}
	//get rks
	rotKeySet := ckks.NewRotationKeySet(params, galEls)

	//rest elapsedRTGParty
	elapsedRTGParty = 0
	elapsedRTGCloud = runTimed(func() {
		for _, galEl := range galEls {
			for _, pi := range P {
				elapsedRTGParty += runTimedParty(func() {
					rtg.GenShare(pi.sk, galEl, crp, pi.rtgShare)
				}, 1)
				rtg.AggregateShare(pi.rtgShare, rtgCombined, rtgCombined)
			}
			rtg.GenRotationKey(rtgCombined, crp, rotKeySet.Keys[galEl])
		}
	})
	elapsedRTGCloud -= elapsedRTGParty

	return rotKeySet
}

//generate collective relinearization key
func rkgphase(params ckks.Parameters, crs utils.PRNG, P []*party) *rlwe.RelinearizationKey {
	l := log.New(os.Stderr, "", 0)

	l.Println("> RKG Phase")

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

	l.Println("> CKG Phase")

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
