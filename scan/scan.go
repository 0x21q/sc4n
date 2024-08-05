package scan

import (
	"errors"
	"fmt"
	"goscan/types"
	"net"
	"os"
)

func ScanInit(scan types.ScanTarget) error {
	switch scan.Mode {
	case types.TCP:
		Tcp(scan.Hosts, scan.Ports, scan.Iface)
	case types.SYN:
		Syn(scan.Hosts, scan.Ports, scan.Iface)
	case types.UDP:
		Udp(scan.Hosts, scan.Ports, scan.Iface)
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
