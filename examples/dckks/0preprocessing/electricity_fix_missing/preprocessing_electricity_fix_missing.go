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
var rFolderFormat = filepath.Join("halfhourly_dataset", "block_%d.csv")
var wFileFormat = filepath.Join("halfhourly_dataset_fix", "block_%d.csv")
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

	newLines := [][]string{}
	previousLine := ""
	newLines = append(newLines, strings.Split("LCLid,tstp,energy(kWh/hh)", ","))
	for _, lo := range lines {
		if strings.Contains(lo, ":00:00") || strings.Contains(lo, ":30:00") {
			lo = strings.Replace(lo, " ", ",", -1)
			lo = strings.Replace(lo, ".0000000", "", -1)    //fix time
			lo = strings.Replace(lo, "Null\r", "0.001", -1) //fix NULL
			// fmt.Printf("%d", li)
			slices := strings.Split(lo, ",")
			if previousLine != "" {
				previousSlice := strings.Split(previousLine, ",")
				if slices[0] == previousSlice[0] {
					previousTimeSlice := strings.Split(previousSlice[2], ":")
					timeSlice := strings.Split(slices[2], ":")

					if timeSlice[1] == previousTimeSlice[1] {
						previousMinutes, err := strconv.Atoi(previousTimeSlice[1])
						if err != nil {
							fmt.Println("Error:", err)
							return
						}
						missingMinutes := (previousMinutes + 30) % 60
						var additionalLine []string
						var additionalTimeStr string
						var missingMinutsStr string
						if missingMinutes == 0 {
							missingMinutsStr = "00"
						} else {
							missingMinutsStr = "30"
						}
						additionalTimeStr = strings.Join([]string{timeSlice[0], missingMinutsStr, timeSlice[2]}, ":")
						additionalLine = []string{slices[0], slices[1], additionalTimeStr, slices[3]}

						newLines = append(newLines, additionalLine)
					}
				}
			} //to debug:C:\Users\23304161\source\repos\lattigo\examples\datasets\electricity
			newLines = append(newLines, slices)
			previousLine = lo
		}
	}

	//create folder
	wFolderFullPath := filepath.Join(wd, relativePath, "halfhourly_dataset_fix")
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
	//create csv file
	wFilePath := fmt.Sprintf(wFileFormat, id)
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
	for _, row := range newLines {
		err := newWriter.Write(row)
		if err != nil {
			log.Fatal("Error writing to CSV:", err)
		}
	}

}
