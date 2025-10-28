package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

func dataMain(basePath string) {
	var filePath, outPath string

	// Create a semaphore with a capacity of 24 to limit the number of concurrent goroutines
	semaphore := make(chan struct{}, 24)
	var wg sync.WaitGroup

	err := filepath.WalkDir(basePath, func(path string, d fs.DirEntry, err error) error {
		// check for pcapng files
		if filepath.Ext(path) == ".pcapng" {
			if err != nil {
				fmt.Println("Error walking the path:", err)
				return err
			}

			filePath = path
			outPath = strings.Replace(path, ".pcapng", "_packetStats.json", 1)
			// Check if the output file already exists
			if _, err := os.Stat(outPath); err == nil {
				fmt.Printf("Output file %s already exists, skipping...\n", outPath)
				return nil
			}

			// Acquire a token from the semaphore before starting a new goroutine
			semaphore <- struct{}{}
			wg.Add(1)
			go func(filePath, outPath string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release the token back to the semaphore when done
				ExtractPacketStats(filePath, outPath, 0)
			}(filePath, outPath)
		}
		return nil
	})
	if err != nil {
		fmt.Println("Error walking the path:", err)
		return
	}

	// Wait for all goroutines to complete
	wg.Wait()
}

func main() {
	var basePath string
	flag.StringVar(&basePath, "p", "../data/", "Base path to the data directory")
	flag.Parse()

	dataMain(basePath)
}
