package scan

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

func Udp(hosts []net.IP, ports []uint16) {
	selected := SelectHost(hosts, true)
	fmt.Printf("[+] Initiating udp scan on: %s\n", selected.String())

	for _, port := range ports {
		if err := sendUdpPacket(selected, port); err != nil {
			fmt.Println("The udp packet cannot be sent")
			continue
		}

		fmt.Println("[+] Sent udp packet to: ", selected.String(), " on port: ", port)

		handle, err := pcapListen(selected)
		if err != nil {
			fmt.Println("The pcap listener cannot be initiated")
			continue
		}
		defer handle.Close()

		packetReceived := handlePacket(handle)
		if !packetReceived {
			fmt.Println("No packets received")
		}
	}
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

func pcapListen(target net.IP) (*pcap.Handle, error) {
	bpfFilter := "icmp[icmptype] == icmp-unreach and src host " + target.String()

	handle, err := pcap.OpenLive("eth0", 1600, false, time.Millisecond*300)
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
	timeout := time.After(2 * time.Second)
	packetReceived := false

	done := make(chan bool)

	go func() {
		for {
			select {
			case packet := <-packetSource.Packets():
				if packet == nil {
					continue
				}
				fmt.Println(packet.String())
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
