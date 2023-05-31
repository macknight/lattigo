package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func DirOperation() {
	fmt.Println("文件夹操作")
	dirEntrys, err := os.ReadDir("C:\\Users\\23304161\\source\\smw\\200Houses_10s_1month_highNE")
	if err != nil {
		panic(err)
	}
	for _, v := range dirEntrys {
		fmt.Println(v.Name())
	}
}

//OpenFile,ReadFile,WriteFile
func FileOperation() {
	//util.MkdirWithFilePath("d1/d2/file")
	fmt.Println("文件夹操作")
	// dirEntrys, err := os.ReadDir("C:\\Users\\23304161\\source\\smw\\200Houses_10s_1month_highNE")
	// if err != nil {
	// 	panic(err)
	// }
	// for _, v := range dirEntrys {
	// 	fmt.Println(v.Name())
	// }
	// fmt.Println("以指定模式打开文件")
	// file, err := os.OpenFile("C:\\Users\\23304161\\source\\smw\\200Houses_10s_1month_highNE\\House_10sec_1month_1.csv",
	// 	os.O_RDWR|os.O_CREATE, 0665)
	// if err != nil {
	// 	panic(err)
	// }
	// defer file.Close()
	fmt.Println("无缓冲区的读")
	data, err := os.ReadFile("C:\\Users\\23304161\\source\\smw\\200Houses_10s_1month_highNE\\House_10sec_1month_1.csv")
	if err != nil {
		panic(err)
	}
	// fmt.Println("数据:", string(data))
	dArray := strings.Split(string(data), "\n")
	fmt.Println("dArray size:", len(dArray))
	// fmt.Println("无缓冲区的写")
	// err = os.WriteFile("f2.csv", data, 0775)
	// if err != nil {
	// 	panic(err)
	// }
}

//带缓冲区的读写
//从多个文件中读入缓冲区，然后一次性写入一个新文件
func FileReadAndWrite() {
	//多次运行，f5会被覆盖，因为没有开启append
	f5, err := os.OpenFile("f5", os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	defer f5.Close()
	writer := bufio.NewWriter(f5)
	fmt.Println("size of buffer writer:", writer.Size())
	for i := 1; i < 5; i++ {
		fileName := fmt.Sprintf("f%v", i)
		data, err := os.ReadFile(fileName)
		if err != nil {
			panic(err)
		}
		data = append(data, '\n')
		writer.Write(data) //写入缓冲区，还没写入到文件里
	}
	writer.Flush() //写入硬盘
}

func main() {
	// FileReadAndWrite()
	FileOperation()
	//DirOperation()
}
