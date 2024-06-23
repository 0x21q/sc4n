package main

import (
	"errors"
	"fmt"
	"os"
)

type Input struct{}

func main() {
	input, err := parse()
	// TODO: error handle
	scan(input)
	// TODO: error handle
}

func parse() (Input, error) {
	arguments := os.Args

	for _, arg := range arguments {
		fmt.Println(arg)
	}

	// TODO: check number of arguments

	// TODO: check syntax of arguments
}

func scan(input Input) {}
