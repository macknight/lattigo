package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// var pathFormat = "./%s/House_10sec_1month_%d.csv"
var rPathFormat = "C:\\Users\\23304161\\source\\Datasets\\electricity\\halfhourly_dataset_fix\\block_%d.csv"

var wFolderFormat = "C:\\Users\\23304161\\source\\Datasets\\electricity\\households_%d"
var wPathFormat = "C:\\Users\\23304161\\source\\Datasets\\electricity\\households_%d\\%s.csv"

const FILE_ROWS = 10240 // element number within a section, 10240, 20000, 20480, 30720, 40960

func main() {
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

	path := fmt.Sprintf(rPathFormat, id)
	lines := ReadCSV(path)
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
	folderFullName := fmt.Sprintf(wFolderFormat, FILE_ROWS)
	_, err := os.Stat(folderFullName)
	if err != nil {
		if os.IsNotExist(err) {
			//create folder if not existed
			err = os.Mkdir(folderFullName, 0755)
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
		newFile, err := os.Create(fmt.Sprintf(wPathFormat, FILE_ROWS, key))
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
