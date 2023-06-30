package main

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ckks"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

func main() {
	paramsDef := ckks.PN13QP218CI // block size = 4096
	params, err := ckks.NewParametersFromLiteral(paramsDef)
	if err != nil {
		fmt.Println("Error:", err)
	}
	encSummationOuts := make([]*rlwe.Ciphertext, 5)
	encSummationOuts[0] = ckks.NewCiphertext(params, 1, params.MaxLevel())

	for i, o := range encSummationOuts {
		_ = i
		_ = o
		if o != nil {
			fmt.Printf("aaa%d\n", i)
		}
		fmt.Println("hello")
	}
}
