package scan

import (
	"fmt"
	"net"
)

func Tcp(hosts []net.IP, ports []uint16) error {
	fmt.Println("Available hosts: ")
	for _, h := range hosts {
		fmt.Println(h)
	}
	return nil
}
