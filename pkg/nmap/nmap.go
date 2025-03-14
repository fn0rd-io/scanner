package nmap

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/Ullaakut/nmap/v3"
	"github.com/fn0rd-io/scanner/pkg/common"
)

// NmapScanner represents an Nmap scanner
type NmapScanner struct {
	scanner *nmap.Scanner
}

func init() {
	common.RegisterScanner("nmap", &NmapScanner{})
}

// portsToString converts a slice of NamedPort to a comma-separated string of port numbers
// with protocol prefixes (t: for TCP, u: for UDP)
func portsToString(ports []common.NamedPort, udp bool) string {
	tcpPorts := make([]string, 0)
	udpPorts := make([]string, 0)

	for _, port := range ports {
		if port.Protocol == common.TCP {
			tcpPorts = append(tcpPorts, fmt.Sprintf("%d", port.Port))
		} else if port.Protocol == common.UDP && udp {
			udpPorts = append(udpPorts, fmt.Sprintf("%d", port.Port))
		}
	}

	result := ""
	if len(tcpPorts) > 0 {
		result += "T:" + strings.Join(tcpPorts, ",")
	}
	if len(udpPorts) > 0 {
		if result != "" {
			result += ","
		}
		result += "U:" + strings.Join(udpPorts, ",")
	}
	return result
}

func (ns *NmapScanner) New(ctx context.Context, targets string, iface string, udp bool) (common.Scanner, error) {
	var opts []nmap.Option
	opts = append(opts,
		nmap.WithTargets(targets),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithOpenOnly(),
		nmap.WithReason(),
		nmap.WithServiceInfo(),
		nmap.WithConnectScan(),
		nmap.WithSkipHostDiscovery(),
		nmap.WithSystemDNS(),
		nmap.WithPorts(portsToString(common.Ports, udp)),
		nmap.WithScripts("vulners", "banner"),
	)
	if iface != "" {
		opts = append(opts, nmap.WithInterface(iface))
	}
	if udp {
		opts = append(opts, nmap.WithUDPScan())
	}
	scanner, err := nmap.NewScanner(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nmap scanner: %w", err)
	}

	return &NmapScanner{scanner: scanner}, nil
}

// Run executes the Nmap scan and returns the results
func (ns *NmapScanner) Run() ([]byte, error) {
	result, _, err := ns.scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to run Nmap scan: %w", err)
	}

	jres, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("result serialization failed: %w", err)
	}

	return jres, nil
}

// Capabilities returns the protocols supported by the Nmap scanner
func (ns *NmapScanner) Capabilities() []common.Protocol {
	capabilities := make([]common.Protocol, 0)
	n, err := ns.New(context.Background(), "127.0.0.1", "", true)
	if err != nil {
		log.Printf("Cannot create Nmap scanner: %v", err)
	} else {
		capabilities = append(capabilities, common.TCP)
		if _, err := n.Run(); err == nil {
			capabilities = append(capabilities, common.UDP)
		} else {
			log.Printf("Limiting Capabilities to TCP-Only: %v", err)
		}
	}
	return capabilities
}
