package util

import (
	"fmt"
	"os"
	"strings"
)

func FileExist(path string) bool {
	fi, err := os.Stat(path)
	if err == nil {
		return !fi.IsDir()
	}
	return os.IsExist(err)
}

func MkdirWithFilePath(filePath string) error {
	paths := strings.Split(filePath, "/")
	paths[len(paths)-1] = ""
	for i, v := range paths {
		if i == len(paths)-1 {
			break
		}
		if i != 0 {
			paths[len(paths)-1] += "/"
		}
		paths[len(paths)-1] += v
	}
	fmt.Println("path:", paths[len(paths)-1])
	return os.MkdirAll(paths[len(paths)-1], 0755)
}
