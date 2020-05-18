package ckks

import (
	"math"
	"math/bits"
)

type poly struct {
	maxDeg uint64
	coeffs []complex128
}

func (p *poly) degree() uint64 {
	return uint64(len(p.coeffs) - 1)
}

func optimalL(M uint64) uint64 {
	L := M >> 1
	a := (1 << L) + (1 << (M - L)) + M - L - 3
	b := (1 << (L + 1)) + (1 << (M - L - 1)) + M - L - 4
	if a > b {
		return L + 1
	}

	return L
}

// EvaluateChebyFast evaluates the input Chebyshev polynomial with the input ciphertext.
// Faster than EvaluateChebyEco but consumes ceil(log(deg)) + 2 levels.
func (eval *evaluator) EvaluateCheby(op *Ciphertext, cheby *ChebyshevInterpolation, evakey *EvaluationKey) (opOut *Ciphertext) {

	C := make(map[uint64]*Ciphertext)

	C[1] = op.CopyNew().Ciphertext()

	eval.MultByConst(C[1], 2/(cheby.b-cheby.a), C[1])
	eval.AddConst(C[1], (-cheby.a-cheby.b)/(cheby.b-cheby.a), C[1])
	eval.Rescale(C[1], eval.ckksContext.scale, C[1])

	return eval.evalCheby(cheby, C, evakey)
}

// EvaluateChebyFastSpecial evaluates the input Chebyshev polynomial with the input ciphertext.
// Slower than EvaluateChebyFast but consumes ceil(log(deg)) + 1 levels.
func (eval *evaluator) EvaluateChebySpecial(ct *Ciphertext, n complex128, cheby *ChebyshevInterpolation, evakey *EvaluationKey) (res *Ciphertext) {

	C := make(map[uint64]*Ciphertext)

	C[1] = ct.CopyNew().Ciphertext()

	eval.MultByConst(C[1], 2/((cheby.b-cheby.a)*n), C[1])
	eval.AddConst(C[1], (-cheby.a-cheby.b)/(cheby.b-cheby.a), C[1])
	eval.Rescale(C[1], eval.params.Scale, C[1])

	return eval.evalCheby(cheby, C, evakey)
}

func (eval *evaluator) evalCheby(cheby *ChebyshevInterpolation, C map[uint64]*Ciphertext, evakey *EvaluationKey) (res *Ciphertext) {

	logDegree := uint64(bits.Len64(cheby.degree()))
	logSplit := (logDegree >> 1) //optimalL(M)

	for i := uint64(2); i < (1 << logSplit); i++ {
		computePowerBasisCheby(i, C, eval, evakey)
	}

	for i := logSplit; i < logDegree; i++ {
		computePowerBasisCheby(1<<i, C, eval, evakey)
	}

	return recurseCheby(logSplit, cheby.Poly(), C, eval, evakey)
}

func computePowerBasisCheby(n uint64, C map[uint64]*Ciphertext, evaluator *evaluator, evakey *EvaluationKey) {

	// Given a hash table with the first three evaluations of the Chebyshev ring at x in the interval a, b:
	// C0 = 1 (actually not stored in the hash table)
	// C1 = (2*x - a - b)/(b-a)
	// C2 = 2*C1*C1 - C0
	// Evaluates the nth degree Chebyshev ring in a recursive manner, storing intermediate results in the hashtable.
	// Consumes at most ceil(sqrt(n)) levels for an evaluation at Cn.
	// Uses the following property: for a given Chebyshev ring Cn = 2*Ca*Cb - Cc, n = a+b and c = abs(a-b)

	if C[n] == nil {

		// Computes the index required to compute the asked ring evaluation
		a := uint64(math.Ceil(float64(n) / 2))
		b := n >> 1
		c := uint64(math.Abs(float64(a) - float64(b)))

		// Recurses on the given indexes
		computePowerBasisCheby(a, C, evaluator, evakey)
		computePowerBasisCheby(b, C, evaluator, evakey)

		// Since C[0] is not stored (but rather seen as the constant 1), only recurses on c if c!= 0
		if c != 0 {
			computePowerBasisCheby(c, C, evaluator, evakey)
		}

		// Computes C[n] = C[a]*C[b]
		//fmt.Println("Mul", C[a].Level(), C[b].Level())
		C[n] = evaluator.MulRelinNew(C[a], C[b], evakey)
		evaluator.Rescale(C[n], evaluator.ckksContext.scale, C[n])

		// Computes C[n] = 2*C[a]*C[b]
		evaluator.Add(C[n], C[n], C[n])

		// Computes C[n] = 2*C[a]*C[b] - C[c]
		if c == 0 {
			evaluator.AddConst(C[n], -1, C[n])
		} else {
			evaluator.Sub(C[n], C[c], C[n])
		}

	}
}

func splitCoeffsCheby(coeffs *poly, split uint64) (coeffsq, coeffsr *poly) {

	// Splits a Chebyshev polynomial p such that p = q*C^degree + r, where q and r are a linear combination of a Chebyshev basis.
	coeffsr = new(poly)
	coeffsr.coeffs = make([]complex128, split)
	if coeffs.maxDeg == coeffs.degree() {
		coeffsr.maxDeg = split - 1
	} else {
		coeffsr.maxDeg = coeffs.maxDeg - (coeffs.degree() - split + 1)
	}

	for i := uint64(0); i < split; i++ {
		coeffsr.coeffs[i] = coeffs.coeffs[i]
	}

	coeffsq = new(poly)
	coeffsq.coeffs = make([]complex128, coeffs.degree()-split+1)
	coeffsq.maxDeg = coeffs.maxDeg

	coeffsq.coeffs[0] = coeffs.coeffs[split]
	for i, j := split+1, uint64(1); i < coeffs.degree()+1; i, j = i+1, j+1 {
		coeffsq.coeffs[i-split] = 2 * coeffs.coeffs[i]
		coeffsr.coeffs[split-j] -= coeffs.coeffs[i]
	}

	return coeffsq, coeffsr
}

func recurseCheby(L uint64, coeffs *poly, C map[uint64]*Ciphertext, evaluator *evaluator, evakey *EvaluationKey) (res *Ciphertext) {

	// Recursively computes the evalution of the Chebyshev polynomial using a baby-set giant-step algorithm.
	if coeffs.degree() < (1 << L) {
		return evaluatePolyFromChebyBasis(coeffs, C, evaluator, evakey)
	}

	var nextPower = uint64(1 << L)
	for nextPower < (coeffs.degree()>>1)+1 {
		nextPower <<= 1
	}

	coeffsq, coeffsr := splitCoeffsCheby(coeffs, nextPower)

	res = recurseCheby(L, coeffsq, C, evaluator, evakey)
	tmp := recurseCheby(L, coeffsr, C, evaluator, evakey)

	evaluator.MulRelin(res, C[nextPower], evakey, res)

	if res.Level() > tmp.Level() {
		evaluator.Rescale(res, evaluator.ckksContext.scale, res)
		evaluator.Add(res, tmp, res)

	} else {
		evaluator.Add(res, tmp, res)
		evaluator.Rescale(res, evaluator.ckksContext.scale, res)
	}

	return res

}

func evaluatePolyFromChebyBasis(coeffs *poly, C map[uint64]*Ciphertext, evaluator *evaluator, evakey *EvaluationKey) (res *Ciphertext) {

	if coeffs.degree() != 0 {
		res = NewCiphertext(evaluator.params, 1, C[coeffs.degree()].Level(), C[1].Scale())
	} else {
		res = NewCiphertext(evaluator.params, 1, C[1].Level(), C[1].Scale())
	}

	for key := coeffs.degree(); key > 0; key-- {
		if key != 0 && (math.Abs(real(coeffs.coeffs[key])) > 1e-14 || math.Abs(imag(coeffs.coeffs[key])) > 1e-14) {
			evaluator.MultByConstAndAdd(C[key], coeffs.coeffs[key], res)
		}
	}

	if math.Abs(real(coeffs.coeffs[0])) > 1e-14 || math.Abs(imag(coeffs.coeffs[0])) > 1e-14 {
		evaluator.AddConst(res, coeffs.coeffs[0], res)
	}

	evaluator.Rescale(res, evaluator.ckksContext.scale, res)

	return
}
