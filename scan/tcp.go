package scan

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func Tcp(hosts []net.IP, ports []uint16, iface net.Interface) {
	selected := SelectHost(hosts, true)
	fmt.Printf("[+] Initiating TCP scan on: %s\n", selected.String())

	for _, port := range ports {
		targetStr := selected.String() + ":" + strconv.FormatUint(uint64(port), 10)
		_, err := net.DialTimeout("tcp", targetStr, time.Second*3)
		if err == nil {
			fmt.Printf("%5d/tcp %8s\n", port, "open")
		} else if nErr, ok := err.(net.Error); ok && (nErr.Timeout() || isFiltered(nErr)) {
			fmt.Printf("%5d/tcp %8s\n", port, "filtered")
		} else {
			fmt.Printf("%5d/tcp %8s\n", port, "closed")
		}
	}
}

func isFiltered(err net.Error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		return strings.Contains(opErr.Err.Error(), "no route to host")
	}
	return false
}
