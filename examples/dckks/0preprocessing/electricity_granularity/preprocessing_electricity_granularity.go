package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var relativePath = filepath.Join("..", "..", "Datasets", "electricity")
var rFolderFormat = filepath.Join("halfhourly_dataset_fix", "block_%d.csv")
var wFolderFormat = "households_%d"
var wFileFormat = filepath.Join("households_%d", "%s.csv")
var wd string

const FILE_ROWS = 10240 // element number within a section, 10240, 20000, 20480, 30720, 40960

func main() {
	var wd, _ = os.Getwd()
	fmt.Println(wd)
	for i := 0; i < 112; i++ {
		genCSV(i)
	}
}

//file reading
func ReadCSV(path string) []string {
	// fmt.Println("reading without buffer:")
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	raw := strings.Replace(string(data), " \r", "", -1)
	raw = strings.Replace(raw, ", ", ",", -1)
	rawArr := strings.Split(raw, "\n")
	arr := rawArr[1 : len(rawArr)-1]
	return arr
}

//trim csv
func genCSV(id int) {

	rFolderPath := fmt.Sprintf(rFolderFormat, id)
	rFolderFullPath := filepath.Join(wd, relativePath, rFolderPath)
	lines := ReadCSV(rFolderFullPath)
	myMap := make(map[string][][]string)

	var file string
	val := 0.0
	for li, lo := range lines {
		lo = strings.Replace(lo, " ", ",", -1)
		lo = strings.Replace(lo, ".0000000", "", -1)    //fix time
		lo = strings.Replace(lo, "Null\r", "0.001", -1) //fix NULL

		slices := strings.Split(lo, ",")
		file = slices[0]
		if _, ok := myMap[file]; !ok {
			myMap[file] = make([][]string, 0)
		}
		//combine 2 rows into 1 row (granularity from 30 min to 1 hour)
		if li%2 == 0 {
			//store
			num, err := strconv.ParseFloat(slices[3], 64)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			val = num
		} else {
			num, err := strconv.ParseFloat(slices[3], 64)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			sum := num + val
			val = 0.0
			sumStr := strconv.FormatFloat(sum, 'f', -1, 64)
			strArr := []string{slices[1], slices[2], sumStr}
			myMap[file] = append(myMap[file], strArr)
		}
	}

	//create folder
	wFolderPath := fmt.Sprintf(wFolderFormat, FILE_ROWS)
	wFolderFullPath := filepath.Join(wd, relativePath, wFolderPath)
	_, err := os.Stat(wFolderFullPath)
	if err != nil {
		if os.IsNotExist(err) {
			//create folder if not existed
			err = os.Mkdir(wFolderFullPath, 0755)
			if err != nil {
				log.Fatal("Error creating folder:", err)
			}
		}
	}

	//write files
	for key, value := range myMap {
		if len(value) < FILE_ROWS {
			fmt.Printf("[%s] has %d rows.\n", key, len(value))
			continue
		}
		//create csv file
		wFilePath := fmt.Sprintf(wFileFormat, FILE_ROWS, key)
		wFileFullPath := filepath.Join(wd, relativePath, wFilePath)
		newFile, err := os.Create(wFileFullPath)
		if err != nil {
			log.Fatal("Error creating file:")
		}
		defer newFile.Close()

		//create csv writer
		newWriter := csv.NewWriter(newFile)
		defer newWriter.Flush()

		//write data into csv file
		for _, row := range value {
			err := newWriter.Write(row)
			if err != nil {
				log.Fatal("Error writing to CSV:", err)
			}
		}
	}
	fmt.Printf("len: %d\n", len(myMap))
}
