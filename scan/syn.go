package scan

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
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

	handleSend, err := pcap.OpenLive(iface.Name, 1600, false, time.Millisecond*10)
	if err != nil {
		fmt.Printf("failed to open device: %v\n", err)
	}
	defer handleSend.Close()

	srcPort, err := getLocalPort()
	if err != nil {
		fmt.Printf("failed to get local port: %v\n", err)
	}

	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(dstPort uint16) {
			defer wg.Done()

			filter := createFilterString(dstPort)

			handleListen, err := pcapListen(iface.Name, filter)
			if err != nil {
				fmt.Printf("failed to open device: %v\n", err)
			}
			defer handleListen.Close()

			err = sendSynPacket(selected, srcPort, dstPort, iface, handleSend)
			if err != nil {
				fmt.Printf("failed to create SYN packet: %v\n", err)
			}

			packetType := receivePacketTCP(handleListen, time.Second)
			if packetType == "SYN-ACK" {
				fmt.Printf("%d/tcp %6s\n", dstPort, "open")
			} else {
				fmt.Printf("%d/tcp %6s\n", dstPort, "closed")
			}
		}(port)
	}
	wg.Wait()
}

func sendSynPacket(
	host net.IP,
	srcPort uint16,
	dstPort uint16,
	iface net.Interface,
	sendHandle *pcap.Handle,
) error {
	buf, err := createSynPacket(host, iface, srcPort, dstPort)
	if err != nil {
		return fmt.Errorf("failed to create SYN packet: %v", err)
	}

	if err := sendHandle.WritePacketData((*buf).Bytes()); err != nil {
		return fmt.Errorf("failed to write packet data: %v", err)
	}

	return nil
}

func createSynPacket(
	dstIP net.IP,
	iface net.Interface,
	srcPort uint16,
	dstPort uint16,
) (*gopacket.SerializeBuffer, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	ethH := createEthHeader(iface)

	srcIP, err := getInterfaceIP(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface IP: %v", err)
	}
	ipH := createIpHeader(srcIP, dstIP)

	tcpH := createTcpHeader(srcPort, dstPort)
	tcpH.SetNetworkLayerForChecksum(ipH)

	if err := gopacket.SerializeLayers(buf, opts, ethH, ipH, tcpH); err != nil {
		return nil, fmt.Errorf("failed to serialize layers: %v", err)
	}

	return &buf, nil
}

func createIpHeader(srcIP, dstIP net.IP) *layers.IPv4 {
	return &layers.IPv4{
		DstIP:    dstIP,
		SrcIP:    srcIP,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
		TTL:      64,
		IHL:      5,
		Id:       33333,
	}
}

func createTcpHeader(srcPort, dstPort uint16) *layers.TCP {
	return &layers.TCP{
		DstPort: layers.TCPPort(dstPort),
		SrcPort: layers.TCPPort(srcPort),
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
}

func createEthHeader(iface net.Interface) *layers.Ethernet {
	return &layers.Ethernet{
		DstMAC:       getNextHopMAC(iface),
		SrcMAC:       iface.HardwareAddr,
		EthernetType: layers.EthernetTypeIPv4,
	}
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

	return waitForPacketTCP(packetSource, timeout)
}

func waitForPacketTCP(
	source *gopacket.PacketSource,
	timeout time.Duration,
) string {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

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
				return "SYN-ACK"
			}

			if tcp.RST && tcp.ACK {
				return "RST-ACK"
			}
		case <-timer.C:
			return "timeout"
		}
	}
}

func getLocalPort() (uint16, error) {
	conn, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return 0, fmt.Errorf("failed to listen: %v", err)
	}
	defer conn.Close()

	addr := conn.Addr().String()
	port, err := strconv.Atoi(strings.Split(addr, ":")[1])
	if err != nil {
		return 0, fmt.Errorf("failed to parse port: %v", err)
	}

	return uint16(port), nil
}

func createFilterString(dstPort uint16) string {
	synack := "(tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack))"
	rstack := "(tcp[tcpflags] & (tcp-rst|tcp-ack) == (tcp-rst|tcp-ack))"
	filter := fmt.Sprintf(
		"tcp and src port %d and (%s or %s)",
		dstPort,
		synack,
		rstack,
	)

	return filter
}

func getNextHopMAC(iface net.Interface) net.HardwareAddr {
	gw, err := gateway.DiscoverGateway()
	if err != nil {
		fmt.Printf("failed to get gateway: %v\n", err)
	}

	mac, err := sendARP(gw, iface)
	if err != nil {
		fmt.Printf("failed to send ARP request to next hop: %v\n", err)
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
