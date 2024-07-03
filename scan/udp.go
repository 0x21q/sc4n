package scan

import (
	"fmt"
	"net"
	"strconv"
)

func Udp(hosts []net.IP, ports []uint16) {
	selected := SelectHost(hosts, true)
	fmt.Printf("[+] Initiating udp scan on: %s\n", selected.String())

	for _, port := range ports {
		targetStr := selected.String() + ":" + strconv.FormatUint(uint64(port), 10)

		udpAddr, err := net.ResolveUDPAddr("udp", targetStr)
		if err != nil {
			fmt.Println("The udp host cannot be resolved")
			continue
		}

		conn, err := net.DialUDP("udp", nil, udpAddr)
		defer conn.Close()

		_, err = conn.Write([]byte("hi"))
		if err != nil {
			println("Write data failed:", err.Error())
			continue // skip for now
		}
	}
}
