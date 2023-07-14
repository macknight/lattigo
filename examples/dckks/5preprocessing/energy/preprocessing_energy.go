package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"strings"
)

// var pathFormat = "./%s/House_10sec_1month_%d.csv"
var rPathFormat = "C:\\Users\\23304161\\source\\Datasets\\energy\\asu_2016-2018.csv"

var wFolderFormat = "C:\\Users\\23304161\\source\\Datasets\\energy\\clients_%d"
var wPathFormat = "C:\\Users\\23304161\\source\\Datasets\\energy\\clients_%d\\%s.csv"

const FILE_ROWS = 20480 // element number within a section, 10240, 20000, 20480, 30720, 40960

func main() {
	genCSV()
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
func genCSV() {

	path := rPathFormat
	lines := ReadCSV(path)
	myMap := make(map[string][][]string)

	var file string
	for _, line := range lines {
		line = strings.Replace(line, " ", ",", -1)
		// line = strings.Replace(line, ".0000000", "", -1)
		// line = strings.Replace(line, "Null\r", "0.001", -1) //fix some broken data

		slices := strings.Split(line, ",")
		file = slices[2] + "_" + slices[3]
		if _, ok := myMap[file]; !ok {
			myMap[file] = make([][]string, 0)
		}
		myMap[file] = append(myMap[file], []string{slices[0], slices[1], slices[4]})
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
