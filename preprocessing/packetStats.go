package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Packet struct {
	SrcIP, DstIP           string
	SrcPort, DstPort       int
	Protocol               int
	Upstream               bool
	Timestamp              int64
	PktLength, PayloadSize int
}

type Flow struct {
	LocalIP, RemoteIP     string
	LocalPort, RemotePort int
	Protocol              int
	ServiceFlowType       string
	DNSName               string
	Packets               []Packet
}

// ExtractPacketStats extracts packet statistics from a pcap file.
// @param numPackets: number of packets to extract per flow, 0 for all packets
func ExtractPacketStats(filePath string, outPath string, numPackets int) {
	// Extract packet statistics from the pcap file and store them in a CSV file
	fmt.Println("========== Processing file: " + filePath + " ==========")

	// get IP addr -- domain name mapping
	dnsMap := constructDNSMap(filePath)
	// store packets for each flow
	flowMap := make(map[string]*Flow)

	// create parser to decode layer data
	var (
		// Will reuse these for each packet
		ethLayer layers.Ethernet
		ip4Layer layers.IPv4
		ip6Layer layers.IPv6
		tcpLayer layers.TCP
		udpLayer layers.UDP
	)
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ip4Layer,
		&ip6Layer,
		&tcpLayer,
		&udpLayer,
	)

	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		fmt.Println("unable to open pcap", err)
		return
	}
	//handle.SetBPFFilter("src port 443 or dst port 443")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true
	//packetSource.DecodeStreamsAsDatagrams = true

	fmt.Println("========== Processing packets ==========")
packetLoop:
	for packet := range packetSource.Packets() {
		// layer processing
		var foundLayerTypes []gopacket.LayerType
		_ = parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		var pktData Packet
		var flowID string
		for _, layerType := range foundLayerTypes {
			switch layerType {
			case layers.LayerTypeIPv4:
				pktData.SrcIP = ip4Layer.SrcIP.String()
				pktData.DstIP = ip4Layer.DstIP.String()
				// determine packet direction
				if isLocalIP(ip4Layer.SrcIP) {
					pktData.Upstream = true
				} else if isLocalIP(ip4Layer.DstIP) {
					pktData.Upstream = false
				} else {
					fmt.Println("Unknown IP address: " + pktData.SrcIP + " or " + pktData.DstIP)
					continue packetLoop
				}
				pktData.Protocol = int(ip4Layer.Protocol)
			case layers.LayerTypeIPv6:
				// ignore for now
			case layers.LayerTypeTCP, layers.LayerTypeUDP:
				// fill in packet data
				pktData.Timestamp = packet.Metadata().Timestamp.UnixMicro()
				pktData.PktLength = len(packet.Data())
				if layerType == layers.LayerTypeTCP {
					pktData.SrcPort = int(tcpLayer.SrcPort)
					pktData.DstPort = int(tcpLayer.DstPort)
					pktData.PayloadSize = len(tcpLayer.Payload)
				} else {
					pktData.SrcPort = int(udpLayer.SrcPort)
					pktData.DstPort = int(udpLayer.DstPort)
					pktData.PayloadSize = len(udpLayer.Payload)
				}
				// filter out unknown DNS names unless within a known port range
				if pktData.Upstream {
					if _, ok := dnsMap[pktData.DstIP]; !ok {
						if pktData.SrcPort < 49000 || pktData.SrcPort > 49100 {
							continue packetLoop
						}
					}
				} else {
					if _, ok := dnsMap[pktData.SrcIP]; !ok {
						if pktData.DstPort < 49000 || pktData.DstPort > 49100 {
							continue packetLoop
						}
					}
				}
				// check if flow exists
				flowID = pktData.getFlowID()
				if _, ok := flowMap[flowID]; !ok {
					if pktData.Upstream {
						flowMap[flowID] = &Flow{
							LocalIP:         pktData.SrcIP,
							RemoteIP:        pktData.DstIP,
							LocalPort:       pktData.SrcPort,
							RemotePort:      pktData.DstPort,
							Protocol:        pktData.Protocol,
							ServiceFlowType: dnsMap[pktData.DstIP],
							DNSName:         dnsMap[pktData.DstIP],
							Packets:         []Packet{pktData},
						}
					} else {
						flowMap[flowID] = &Flow{
							LocalIP:         pktData.DstIP,
							RemoteIP:        pktData.SrcIP,
							LocalPort:       pktData.DstPort,
							RemotePort:      pktData.SrcPort,
							Protocol:        pktData.Protocol,
							ServiceFlowType: dnsMap[pktData.SrcIP],
							DNSName:         dnsMap[pktData.SrcIP],
							Packets:         []Packet{pktData},
						}
					}
				} else {
					// check if max number of packets per flow is reached
					if numPackets > 0 && len(flowMap[flowID].Packets) >= numPackets {
						continue packetLoop
					}
					flowMap[flowID].Packets = append(flowMap[flowID].Packets, pktData)
				}
			}
		}
	}
	// store flow data in a json file
	fmt.Printf("========== Writing to file: %s ==========\n", outPath)
	jsonString, err := json.Marshal(flowMap)
	if err != nil {
		fmt.Println(err)
		panic("unable to marshal flow data")
	}
	err = os.WriteFile(outPath, jsonString, 0644)
	if err != nil {
		fmt.Println(err)
		panic("unable to write to file")
	}
}

func (flow *Flow) getFlowID() string {
	return flow.LocalIP + ":" + strconv.Itoa(flow.LocalPort) + "-" + flow.RemoteIP + ":" + strconv.Itoa(flow.RemotePort) + "@" + strconv.Itoa(flow.Protocol)
}

func (packet *Packet) getFlowID() string {
	if packet.Upstream {
		return packet.SrcIP + ":" + strconv.Itoa(packet.SrcPort) + "-" + packet.DstIP + ":" + strconv.Itoa(packet.DstPort) + "@" + strconv.Itoa(packet.Protocol)
	} else {
		return packet.DstIP + ":" + strconv.Itoa(packet.DstPort) + "-" + packet.SrcIP + ":" + strconv.Itoa(packet.SrcPort) + "@" + strconv.Itoa(packet.Protocol)
	}
}

func isLocalIP(ipAddr net.IP) bool {
	privateSubnets := []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"}
	unswSubnets := []string{"149.171.0.0/16"}
	localSubnets := append(privateSubnets, unswSubnets...)
	for _, subnet := range localSubnets {
		_, ipNet, _ := net.ParseCIDR(subnet)
		if ipNet.Contains(ipAddr) {
			return true
		}
	}
	return false
}

func constructDNSMap(filePath string) map[string]string {
	// Construct a map of DNS queries and responses
	fmt.Println("========== Mapping DNS names for " + filePath + " ==========")
	dnsMap := make(map[string]string)
	// check if dns map file already exists
	dnsMapPath := filepath.Dir(filePath) + "/dns_map.json"
	if _, err := os.Stat(dnsMapPath); err == nil {
		fmt.Println("DNS map already exists, reading from file")
		dnsMapFile, err := os.ReadFile(dnsMapPath)
		if err != nil {
			fmt.Println(err)
			panic("unable to read DNS map file")
		}
		err = json.Unmarshal(dnsMapFile, &dnsMap)
		if err != nil {
			fmt.Println(err)
			panic("unable to unmarshal DNS map")
		}
		return dnsMap
	}

	// create parser to decode layer data
	var (
		// Will reuse these for each packet
		ethLayer layers.Ethernet
		ip4Layer layers.IPv4
		ip6Layer layers.IPv6
		tcpLayer layers.TCP
		udpLayer layers.UDP
		dnsLayer layers.DNS
	)
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ip4Layer,
		&ip6Layer,
		&tcpLayer,
		&udpLayer,
		&dnsLayer,
	)

	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		panic("unable to open pcap")
	}
	err = handle.SetBPFFilter("udp and src port 53") // only check DNS responses
	if err != nil {
		panic("unable to set BPF filter")
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	for packet := range packetSource.Packets() {
		var foundLayerTypes []gopacket.LayerType
		_ = parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		for _, layerType := range foundLayerTypes {
			switch layerType {
			case layers.LayerTypeDNS:
				if dnsLayer.QR {
					for _, answer := range dnsLayer.Answers {
						dnsRecord := answer
						if dnsRecord.Type == layers.DNSTypeA {
							dnsName := string(dnsRecord.Name)
							dnsIP := dnsRecord.IP.String()
							dnsMap[dnsIP] = dnsName
						}
					}
				}
			}
		}
	}
	// write map to a file in the same directory as the pcap file
	fmt.Println("========== Writing DNS map to file ==========")
	jsonString, err := json.Marshal(dnsMap)
	if err != nil {
		fmt.Println(err)
		panic("unable to marshal DNS map")
	}
	err = os.WriteFile(dnsMapPath, jsonString, 0644)
	if err != nil {
		fmt.Println(err)
		panic("unable to write to file")
	}
	return dnsMap
}
