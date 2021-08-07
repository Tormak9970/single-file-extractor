package main

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Tormak9970/single-file-extractor/logger"
	"github.com/Tormak9970/single-file-extractor/reader/hash"
	"github.com/Tormak9970/single-file-extractor/reader/tor"
)

//* Build Command: go build -o fileExtractor.exe main.go

func zlipDecompress(buff []byte) ([]byte, error) {
	b := bytes.NewReader(buff)
	r, err := zlib.NewReader(b)

	if err != nil {
		fmt.Print(err)
		return nil, err
	}
	var out bytes.Buffer
	io.Copy(&out, r)

	return out.Bytes(), nil
}

func writeFile(data []byte, dir string, outputDir string) {
	if dir == "" {
		return
	}
	path := outputDir + dir

	destination, err := os.Create(path)
	logger.Check(err)

	destination.Write(data)
	destination.Close()
}

func main() {
	var torFiles []string
	var targetHashes []string

	hashPath := ""
	outputDir := ""
	if len(os.Args) >= 4 {
		err := json.Unmarshal([]byte(os.Args[1]), &torFiles)
		if err != nil {
			fmt.Println(err)
		}

		outputDir = os.Args[2]
		hashPath = os.Args[3]
		err2 := json.Unmarshal([]byte(os.Args[4]), &targetHashes)
		if err2 != nil {
			fmt.Println(err2)
		}
	}
	if len(torFiles) == 0 || len(targetHashes) == 0 || outputDir == "" || hashPath == "" {
		return
	}

	hashes := hash.Read(hashPath)

	if len(torFiles) == 1 {
		torName := torFiles[0]
		torFiles = []string{}

		f, _ := os.Open(torName)
		fi, _ := f.Stat()

		switch mode := fi.Mode(); {
		case mode.IsDir():
			files, _ := ioutil.ReadDir(torName)

			for _, f := range files {
				file := filepath.Join(torName, f.Name())

				fileMode := f.Mode()

				if fileMode.IsRegular() {
					if filepath.Ext(file) == ".tor" {
						torFiles = append(torFiles, file)
					}
				}
			}
		case mode.IsRegular():
			torFiles = append(torFiles, torName)
		}
	}

	data := tor.ReadAll(torFiles)

	filesNoHash := 0

	filesAttempted := 0
	start := time.Now()

	log.Printf("using %d workerpools to instantiate server instances", runtime.NumCPU())
	lengthDat := len(data)
	found := false
	for _, data := range data {
		if hashData, ok := hashes[data.FileID]; ok {
			filesAttempted++
			hashData := hashData
			data := data
			if hashData.PH == targetHashes[0] && hashData.SH == targetHashes[1] {
				log.Println("matched!")
				found = true
				f, _ := os.Open(data.TorFile)
				defer f.Close()
				f.Seek(int64(data.Offset+uint64(data.HeaderSize)), 0)
				fileData := make([]byte, data.CompressedSize)
				f.Read(fileData)
				if data.CompressionMethod == 0 {
					writeFile(fileData, hashData.Filename[strings.LastIndex(hashData.Filename, "/"):], outputDir)
				} else {
					fileData, err := zlipDecompress(fileData)
					logger.Check(err)
					writeFile(fileData, hashData.Filename[strings.LastIndex(hashData.Filename, "/"):], outputDir)
				}
				break
			}
			fmt.Println(filesAttempted, lengthDat)
		} else {
			filesNoHash++
		}
	}

	diff := time.Now().Sub(start)
	log.Println("duration", fmt.Sprintf("%s", diff))
	if found {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}
