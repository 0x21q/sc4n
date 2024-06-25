package main

import (
	"fmt"
	"goscan/args"
	"os"
)

func main() {
	input, err := args.Load()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(input)

	//Scan(input)
	// TODO: error handle
}
