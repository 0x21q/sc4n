package scan

import (
	"errors"
	"goscan/types"
)

func ScanInit(target types.ScanTarget) error {
	switch target.Mode {
	case types.TCP:
		return Tcp(target.Hosts, target.Ports)
	case types.SYN:
		return Syn(target.Hosts, target.Ports)
	case types.UDP:
		return Udp(target.Hosts, target.Ports)
	default:
		return errors.New("Unknown scan mode")
	}
}
