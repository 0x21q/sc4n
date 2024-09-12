package scan

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	// needed for the gateway MAC discovery
	"github.com/jackpal/gateway"
	"github.com/mdlayher/arp"
)

func Syn(hosts []net.IP, ports []uint16, iface net.Interface) {
	selected := SelectHost(hosts, true)

	handleSend, err := pcap.OpenLive(iface.Name, 65535, false, time.Millisecond*10)
	if err != nil {
		fmt.Printf("failed to open device: %v\n", err)
	}
	defer handleSend.Close()

	synackFilter := "(tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack))"
	rstackFilter := "(tcp[tcpflags] & (tcp-rst|tcp-ack) == (tcp-rst|tcp-ack))"
	bpfFilter := synackFilter + " or " + rstackFilter + " and src host " + selected.String()

	for _, port := range ports {
		if err := sendSynPacket(selected, port, iface, handleSend); err != nil {
			fmt.Printf("failed to create SYN packet: %v\n", err)
			continue
		}

		handleListen, err := pcapListen(iface.Name, bpfFilter)
		if err != nil {
			fmt.Printf("failed to open device: %v\n", err)
			continue
		}
		defer handleListen.Close()

		packetType := receivePacketTCP(handleListen, time.Second)
		if packetType == "SYN-ACK" {
			fmt.Printf("%d/tcp %6s\n", port, "open")
		} else {
			fmt.Printf("%d/tcp %6s\n", port, "closed")
		}
	}
}

func sendSynPacket(host net.IP, port uint16, iface net.Interface, sendHandle *pcap.Handle) error {
	buf := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ethH := layers.Ethernet{
		DstMAC:       getNextHopMAC(iface),
		SrcMAC:       iface.HardwareAddr,
		EthernetType: layers.EthernetTypeIPv4,
	}

	srcIP, err := getInterfaceIP(iface)
	if err != nil {
		return fmt.Errorf("failed to get interface IP: %v", err)
	}

	ipH := layers.IPv4{
		DstIP:    host,
		SrcIP:    srcIP,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
		IHL:      5,
		Id:       33333,
	}

	tcpH := layers.TCP{
		DstPort: layers.TCPPort(port),
		SrcPort: layers.TCPPort(59595),
		SYN:     true,
		Seq:     123456789,
		Window:  1024,
		Options: []layers.TCPOption{
			{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData:   []byte{0x05, 0xb4},
			},
		},
	}

	tcpH.SetNetworkLayerForChecksum(&ipH)

	if err := gopacket.SerializeLayers(buf, opts, &ethH, &ipH, &tcpH); err != nil {
		return fmt.Errorf("failed to serialize layers: %v", err)
	}

	if err := sendHandle.WritePacketData(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write packet data: %v", err)
	}

	return nil
}

func getInterfaceIP(iface net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface addresses: %v", err)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("interface has no addresses")
	}

	if len(strings.Split(addrs[0].String(), "/")) != 2 {
		return nil, fmt.Errorf("invalid address format")
	}

	return net.ParseIP(strings.Split(addrs[0].String(), "/")[0]), nil
}

func receivePacketTCP(handle *pcap.Handle, timeout time.Duration) string {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	res := make(chan bool)
	packetType := ""

	go waitForPacketTCP(packetSource, res, timeout, &packetType)

	<-res
	return packetType

}

func waitForPacketTCP(
	source *gopacket.PacketSource,
	res chan<- bool,
	timeout time.Duration,
	packetType *string,
) {
	for {
		select {
		case packet := <-(*source).Packets():
			if packet == nil {
				continue
			}

			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer == nil {
				continue
			}
			tcp, _ := tcpLayer.(*layers.TCP)

			if tcp.SYN && tcp.ACK {
				*packetType = "SYN-ACK"
				res <- true
				return
			}

			if tcp.RST && tcp.ACK {
				*packetType = "RST-ACK"
				res <- true
				return
			}
		case <-time.After(timeout):
			*packetType = ""
			res <- true
			return
		}
	}
}

func getNextHopMAC(iface net.Interface) net.HardwareAddr {
	gw, err := gateway.DiscoverGateway()
	if err != nil {
		fmt.Printf("failed to get gateway: %v\n", err)
	}

	mac, err := sendARP(gw, iface)
	if err != nil {
		fmt.Printf("failed to send ARP request to next hop device: %v\n", err)
		return net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}

	return mac
}

func sendARP(gateway net.IP, iface net.Interface) (net.HardwareAddr, error) {
	client, err := arp.Dial(&iface)
	if err != nil {
		return nil, fmt.Errorf("failed to dial ARP: %v\n", err)
	}
	defer client.Close()

	ip, ok := netip.AddrFromSlice(gateway.To4())
	if !ok {
		return nil, fmt.Errorf("failed to convert IP: %v\n", err)
	}

	mac, err := client.Resolve(ip)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve MAC: %v\n", err)
	}

	return mac, nil
}
