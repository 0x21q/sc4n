package scan

import (
	"errors"
	"fmt"
	"goscan/types"
	"net"
	"os"
	"time"

	"github.com/gopacket/gopacket/pcap"
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

func pcapListen(ifaceName string, filter string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(ifaceName, 1600, false, time.Millisecond*10)
	if err != nil {
		return nil, err
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, err
	}

	return handle, nil
}
