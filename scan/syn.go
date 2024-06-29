package scan

import (
	"fmt"
	"net"
)

func Syn(hosts []net.IP, ports []uint16) {
	fmt.Println("Doing tcp syn scan")
}
