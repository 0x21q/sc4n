package scan

import (
	"errors"
	"fmt"
	"goscan/types"
	"net"
	"os"
	"sort"
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
		return nil, fmt.Errorf("failed to open device: %v", err)
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to set BPF filter: %v", err)
	}

	return handle, nil
}

func parseResChan(resChan chan types.ScanResult) []types.ScanResult {
	var results []types.ScanResult
	for res := range resChan {
		results = append(results, res)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})

	return results
}

func printResults(results []types.ScanResult) {
	opened := false
	for _, res := range results {
		if res.State == types.OPEN {
			opened = true
			fmt.Printf("%5d/tcp %8s\n", res.Port, "open")
		} else if res.State == types.FILTERED {
			opened = true
			fmt.Printf("%5d/tcp %8s\n", res.Port, "filtered")
		}
	}
	if !opened {
		for _, res := range results {
			fmt.Printf("%5d/tcp %8s\n", res.Port, "closed")
		}
	}
}

func createFilterString(
	host net.IP,
	dstPort uint16,
	mode types.ScanMode,
) string {
	var filter string

	switch mode {
	case types.SYN:
		synack := "(tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack))"
		rstack := "(tcp[tcpflags] & (tcp-rst|tcp-ack) == (tcp-rst|tcp-ack))"
		filter = fmt.Sprintf(
			"tcp and src host %s and src port %d and (%s or %s)",
			host.String(),
			dstPort,
			synack,
			rstack,
		)
	case types.UDP:
		icmp := fmt.Sprintf(
			"icmp[icmptype] == icmp-unreach and icmp[30:2] == %d",
			dstPort,
		)
		filter = fmt.Sprintf(
			"%s and src host %s",
			icmp,
			host.String(),
		)
	}
	return filter
}
