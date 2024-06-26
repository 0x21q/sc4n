package main

import (
	"fmt"
	"goscan/args"
	"goscan/scan"
	"os"
)

func main() {
	target, err := args.Load()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := scan.ScanInit(target); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
