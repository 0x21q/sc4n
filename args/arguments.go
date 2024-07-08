package args

import (
	"errors"
	"flag"
	"fmt"
	"goscan/types"
	"net"
	"strconv"
	"strings"
)

func Load() (types.ScanTarget, error) {
	raw_host := flag.String(
		"h",
		"",
		"Specify host to scan (e.g. -h <domain> or -h <ip>)",
	)
	raw_ports := flag.String(
		"p",
		"",
		"Specify port(s) to scan (e.g. -p <p1> or -p <p1, p2, ...> or -p <p1-p2>)",
	)
	raw_iface := flag.String(
		"i",
		"",
		"Specify interface to use (e.g. -i <if>)",
	)
	tcp := flag.Bool("t", false, "Specify to perform TCP scan (default)")
	syn := flag.Bool("s", false, "Specify to perform TCP syn scan")
	udp := flag.Bool("u", false, "Specify to perform UDP scan")
	flag.Parse()

	if *raw_host == "" || *raw_ports == "" {
		return types.ScanTarget{}, errors.New("Unspecified host or port")
	}

	hosts, err := net.LookupIP(*raw_host)
	if err != nil {
		return types.ScanTarget{}, err
	}

	ports, err := parsePorts(*raw_ports)
	if err != nil {
		return types.ScanTarget{}, err
	}

	iface, err := selectInterface(*raw_iface)
	if err != nil {
		return types.ScanTarget{}, err
	}
	fmt.Println("[+] Using interface: " + iface.Name)

	mode, err := checkScanFlags(tcp, syn, udp)
	if err != nil {
		return types.ScanTarget{}, err
	}

	return types.ScanTarget{
			Hosts: hosts,
			Ports: ports,
			Mode:  mode,
			Iface: iface,
		},
		nil
}

func parsePorts(raw_ports string) ([]uint16, error) {
	if strings.Contains(raw_ports, "-") {
		return parseDash(raw_ports)
	} else if strings.Contains(raw_ports, ",") {
		return parseComma(raw_ports)
	} else {
		return parseSingle(raw_ports)
	}
}

func parseDash(raw_ports string) ([]uint16, error) {
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

func parseComma(raw_ports string) ([]uint16, error) {
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

func parseSingle(raw_ports string) ([]uint16, error) {
	n, err := strconv.ParseUint(raw_ports, 10, 16)
	if err != nil {
		return nil, errors.New("Invalid port format")
	} else {
		return []uint16{uint16(n)}, nil
	}
}

func selectInterface(raw_interface string) (net.Interface, error) {
	if raw_interface != "" {
		iface, err := net.InterfaceByName(raw_interface)
		if err != nil {
			return net.Interface{}, err
		}
		return *iface, nil
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, err
	}

	// going through in reverse to select loopback as a last
	// choice when checking for running interfaces
	for i := len(interfaces) - 1; i >= 0; i-- {
		if interfaces[i].Flags&net.FlagRunning == net.FlagRunning {
			return interfaces[i], nil
		}
	}
	return net.Interface{}, errors.New("No interface found")
}

func checkScanFlags(tcp *bool, syn *bool, udp *bool) (types.ScanMode, error) {
	if (*tcp && *syn) || (*tcp && *udp) || (*syn && *udp) {
		return types.SYN,
			errors.New("Mutiple scan modes are not yet supported")
	}

	var mode types.ScanMode
	switch {
	case *syn:
		mode = types.SYN
	case *udp:
		mode = types.UDP
	default:
		mode = types.TCP
	}

	return mode, nil
}
