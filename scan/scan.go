package scan

import (
	"errors"
	"goscan/types"
)

func ScanInit(target types.ScanTarget) error {
	switch target.Mode {
	case types.TCP:
		Tcp(target.Hosts, target.Ports)
	case types.SYN:
		Syn(target.Hosts, target.Ports)
	case types.UDP:
		Udp(target.Hosts, target.Ports)
	default:
		return errors.New("Unknown scan mode")
	}
	return nil
}
