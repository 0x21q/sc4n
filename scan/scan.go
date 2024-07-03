package scan

import (
	"errors"
	"fmt"
	"goscan/types"
	"net"
	"os"
)

func ScanInit(target types.ScanTarget) error {
	switch target.Mode {
	case types.TCP:
		Tcp(target.Hosts, target.Ports)
	case types.SYN:
		Syn(target.Hosts, target.Ports)
	case types.UDP:
		Udp(target.Hosts, target.Ports)
	default:
		return errors.New("Unknown scan mode")
	}
	return nil
}

func SelectHost(hosts []net.IP, verbose bool) net.IP {
	if verbose {
		fmt.Println("[+] Available hosts: ")
	}

	for _, h := range hosts {
		if verbose {
			fmt.Println(h)
		}
		if h.To4() != nil {
			return h
		}
	}
	// explicit assert check
	if len(hosts) < 1 {
		fmt.Println("No hosts, which should not happen")
		os.Exit(1)
	}
	return hosts[0]
}
