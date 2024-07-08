package types

import (
	"net"
)

type ScanMode uint8

const (
	TCP ScanMode = iota
	SYN
	UDP
)

type ScanState uint8

const (
	UNKNOWN ScanState = iota
	OPEN
	FILTERED
	CLOSED
)

type ScanTarget struct {
	Hosts []net.IP
	Ports []uint16
	Mode  ScanMode
	Iface net.Interface
}

type ScanResult struct {
	Host  net.IP
	Port  uint16
	State ScanState
}
