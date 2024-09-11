package scan

import (
	"fmt"
	"net"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

func Syn(hosts []net.IP, ports []uint16, iface net.Interface) {
	selected := SelectHost(hosts, true)

	handle, err := pcap.OpenLive(iface.Name, 65535, false, pcap.BlockForever)
	if err != nil {
		fmt.Printf("failed to open device: %v\n", err)
	}
	defer handle.Close()

	for _, port := range ports {
		packet, err := createSynPacket(selected, port, iface)
		if err != nil {
			fmt.Printf("failed to create SYN packet: %v\n", err)
			continue
		}
		handle.WritePacketData(packet)
		fmt.Println("sent SYN packet")
	}
}

func createSynPacket(host net.IP, port uint16, iface net.Interface) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface addresses: %v", err)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("interface has no addresses")
	}

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	srcIPStr := strings.Split(addrs[0].String(), "/")[0]

	ipH := layers.IPv4{
		DstIP:    host,
		SrcIP:    net.ParseIP(srcIPStr),
		Protocol: layers.IPProtocolTCP,
	}

	tcpH := layers.TCP{
		DstPort: layers.TCPPort(port),
		SrcPort: layers.TCPPort(12345),
		SYN:     true,
	}

	tcpH.SetNetworkLayerForChecksum(&ipH)

	errS := gopacket.SerializeLayers(buf, opts, &ipH, &tcpH)
	if errS != nil {
		return nil, errS
	}

	return buf.Bytes(), nil
}
