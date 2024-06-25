package args

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Input struct {
	hosts []net.IP
	ports []uint16
}

func Load() (Input, error) {
	raw_host := flag.String("h", "", "Specify host to scan (e.g. -h <domain> or -h <ip>)")
	raw_ports := flag.String("p", "", "Specify port(s) to scan (e.g. -p <port> or -p <port1,port2,port3> or -p <port1-port2>)")
	flag.Parse()

	if *raw_host == "" || *raw_ports == "" {
		return Input{}, errors.New("Unspecified parameters")
	}

	hosts, err := net.LookupIP(*raw_host)
	if err != nil {
		return Input{}, err
	}

	ports, err := parse_ports(*raw_ports)
	if err != nil {
		return Input{}, err
	}

	return Input{hosts, ports}, nil
}

func parse_ports(raw_ports string) ([]uint16, error) {
	if strings.Contains(raw_ports, "-") {
		return parse_dash(raw_ports)
	} else if strings.Contains(raw_ports, ",") {
		return parse_comma(raw_ports)
	} else {
		return parse_single(raw_ports)
	}
}

func parse_dash(raw_ports string) ([]uint16, error) {
	splits := strings.Split(raw_ports, "-")
	if len(splits) != 2 {
		return nil, errors.New("Invalid port format")
	}

	n1, err := strconv.ParseUint(splits[0], 10, 16)
	if err != nil {
		return nil, errors.New("Invalid first port number")
	}

	n2, err := strconv.ParseUint(splits[1], 10, 16)
	if err != nil {
		return nil, errors.New("Invalid second port number")
	}

	if n2 < n1 {
		n1, n2 = n2, n1
	}

	var ports []uint16
	for i := n1; i <= n2; i++ {
		ports = append(ports, uint16(i))
	}

	return ports, nil
}

func parse_comma(raw_ports string) ([]uint16, error) {
	var ports []uint16
	splits := strings.Split(raw_ports, ",")

	for _, n := range splits {
		n, err := strconv.ParseUint(n, 10, 16)
		if err != nil {
			return nil, errors.New("Invalid port list format")
		} else {
			ports = append(ports, uint16(n))
		}
	}

	return ports, nil
}

func parse_single(raw_ports string) ([]uint16, error) {
	n, err := strconv.ParseUint(raw_ports, 10, 16)
	if err != nil {
		return nil, errors.New("Invalid port format")
	} else {
		return []uint16{uint16(n)}, nil
	}
}
