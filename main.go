package main

import (
	"fmt"
	"goscan/args"
	"goscan/scan"
	"os"
)

func main() {
	if target, err := args.Load(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else if err := scan.ScanInit(target); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
