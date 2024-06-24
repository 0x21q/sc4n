package main

import (
	"flag"
	"log"
	"net"
)

type Input struct {
	host  net.IP // not sure
	ports []uint16
}

func main() {
	input, err := load_arguments()
	if err != nil {
		log.Fatal(err)
		return
	}

	scan(input)
	// TODO: error handle
}

func load_arguments() (Input, error) {
	host := flag.String("h", "", "Specify host to scan (e.g. -h <domain> or -h <ip>)")
	ports := flag.String("p", "", "Specify port(s) to scan (e.g. -p <port> or -p <port1,port2,port3> or -p <port1-port2>)")
	flag.Parse()

	var input Input

	if parsed := net.ParseIP(*host); parsed != nil {
		input.host = parsed
	} else {
	}

	// check loaded arguments
}

func scan(input Input) {}
