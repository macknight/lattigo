package main

import (
	"fmt"
	"os"
)

func main() {
	num := 20
	str := "hello"
	fileName := fmt.Sprintf("%s%d.txt", str, num)

	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	originalOutput := os.Stdout
	defer func() { os.Stdout = originalOutput }()
	os.Stdout = file

	fmt.Println("This will be written to the file", fileName)
}
