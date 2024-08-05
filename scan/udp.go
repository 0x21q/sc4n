package scan

import (
	"fmt"
	"goscan/utils"
	"net"
	"strconv"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

func Udp(hosts []net.IP, ports []uint16, iface net.Interface) {
	selected := SelectHost(hosts, true)
	fmt.Printf("[+] Initiating udp scan on: %s\n", selected.String())

	// since icmp is not deterministic and can be limited, the scanning
	// consists of mutiple iterations, the ports without icmp response
	// are scanned repeatedly until they are presumed as open or filtered

	repeat_count := 3

	scanAgain := scanPorts(selected, ports, iface)
	for i := 0; i < repeat_count; i++ {
		scanAgain = scanPorts(selected, scanAgain, iface)
	}

	for _, port := range ports {
		if utils.Contains(scanAgain, port) {
			fmt.Printf("%5d/udp %13s\n", port, "open/filtered")
		} else {
			fmt.Printf("%5d/udp %13s\n", port, "closed")
		}
	}
}

func scanPorts(target net.IP, ports []uint16, iface net.Interface) []uint16 {
	var scanAgain []uint16

	for _, port := range ports {
		if err := sendUdpPacket(target, port); err != nil {
			fmt.Printf("The udp packet cannot be sent (port %d)", port)
			continue
		}

		handle, err := pcapListen(target, iface.Name)
		if err != nil {
			fmt.Printf("The pcap listener cannot be initiated (port %d)", port)
			continue
		}
		defer handle.Close()

		icmpReceived := handlePacket(handle)
		if !icmpReceived {
			scanAgain = append(scanAgain, port)
		}
	}

	return scanAgain
}

func sendUdpPacket(target net.IP, port uint16) error {
	targetStr := target.String() + ":" + strconv.FormatUint(uint64(port), 10)

	udpAddr, err := net.ResolveUDPAddr("udp", targetStr)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err = conn.Write([]byte("hi")); err != nil {
		return err
	}

	return nil
}

func pcapListen(target net.IP, ifaceName string) (*pcap.Handle, error) {
	bpfFilter := "icmp[icmptype] == icmp-unreach and src host " + target.String()

	handle, err := pcap.OpenLive(ifaceName, 1600, false, time.Millisecond*10)
	if err != nil {
		return nil, err
	}

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		handle.Close()
		return nil, err
	}

	return handle, nil
}

func handlePacket(handle *pcap.Handle) bool {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timeout := time.After(3 * time.Second)
	packetReceived := false

	done := make(chan bool)

	go func() {
		for {
			select {
			case packet := <-packetSource.Packets():
				if packet == nil {
					continue
				}
				packetReceived = true
				done <- true
				return
			case <-timeout:
				done <- true
				return
			}
		}
	}()

	<-done
	return packetReceived
}
