package scan

import (
	"fmt"
	"goscan/types"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func Tcp(hosts []net.IP, ports []uint16, iface net.Interface) {
	selected := SelectHost(hosts, true)
	fmt.Printf("[+] Initiating TCP scan on: %s\n", selected.String())

	resChan := make(chan types.ScanResult, len(ports))
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p uint16) {
			defer wg.Done()
			sRes := types.ScanResult{Host: selected, Port: p, State: types.UNKNOWN}

			targetStr := selected.String() + ":" + strconv.FormatUint(uint64(port), 10)
			_, err := net.DialTimeout("tcp", targetStr, time.Second)
			if err == nil {
				sRes.State = types.OPEN
			} else if nErr, ok := err.(net.Error); ok && (nErr.Timeout() || isFiltered(nErr)) {
				sRes.State = types.FILTERED
			} else {
				sRes.State = types.CLOSED
			}
			resChan <- sRes
		}(port)
	}
	go func() {
		wg.Wait()
		close(resChan)
	}()

	results := parseResChan(resChan)
	printResults(results)
}

func isFiltered(err net.Error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		return strings.Contains(opErr.Err.Error(), "no route to host")
	}
	return false
}
