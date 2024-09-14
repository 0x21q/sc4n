package scan

import (
	"fmt"
	"goscan/types"
	"net"
	"slices"
	"sort"
	"sync"
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

	var scanAgain []uint16
	var scanResults []uint16
	limit := 6

	for i := 0; i < len(ports)/limit; i++ {
		scanAgain = scanPortsUDP(selected, ports[i*limit:(i+1)*limit], iface)
		for j := 0; j < 3; j++ {
			scanAgain = scanPortsUDP(selected, scanAgain, iface)
		}
		scanResults = append(scanResults, scanAgain...)
	}

	for _, port := range ports {
		if len(scanResults) == 0 {
			fmt.Printf("%5d/udp %13s\n", port, "closed")
		} else if slices.Contains(scanResults, port) {
			fmt.Printf("%5d/udp %13s\n", port, "open/filtered")
		}
	}
}

func scanPortsUDP(target net.IP, ports []uint16, iface net.Interface) []uint16 {
	resChan := make(chan types.ScanResult, len(ports))
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(dstPort uint16) {
			defer wg.Done()

			sRes := types.ScanResult{Host: target, Port: dstPort, State: types.UNKNOWN}
			filter := createFilterString(target, dstPort, types.UDP)

			handle, err := pcapListen(iface.Name, filter)
			if err != nil {
				fmt.Printf("The pcap listener cannot be initiated (p. %d)\n", dstPort)
				resChan <- sRes
				return
			}
			defer handle.Close()

			if err := sendUdpPacket(target, dstPort); err != nil {
				fmt.Printf("The udp packet cannot be sent (p. %d)\n", dstPort)
				resChan <- sRes
				return
			}

			sRes.State = receivePacketUDP(handle, time.Second*3)
			resChan <- sRes
		}(port)
	}
	go func() {
		wg.Wait()
		close(resChan)
	}()

	return parseResChanUDP(resChan)
}

func sendUdpPacket(target net.IP, port uint16) error {
	targetStr := fmt.Sprintf("%s:%d", target.String(), port)

	udpAddr, err := net.ResolveUDPAddr("udp", targetStr)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err = conn.Write([]byte("hi!")); err != nil {
		return err
	}

	return nil
}

func receivePacketUDP(handle *pcap.Handle, t time.Duration) types.ScanState {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	return waitForPacketUDP(packetSource, t)
}

func waitForPacketUDP(
	source *gopacket.PacketSource,
	timeout time.Duration,
) types.ScanState {
	for {
		select {
		case packet := <-source.Packets():
			if packet == nil {
				continue
			}
			return types.CLOSED
		case <-time.After(timeout):
			return types.OPEN_FILTERED
		}
	}
}

func parseResChanUDP(resChan chan types.ScanResult) []uint16 {
	var openPorts []uint16
	for res := range resChan {
		if res.State == types.OPEN_FILTERED {
			openPorts = append(openPorts, res.Port)
		}
	}

	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i] < openPorts[j]
	})

	return openPorts
}
