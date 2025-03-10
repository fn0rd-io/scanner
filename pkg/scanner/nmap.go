package scanner

import (
	"context"
	"fmt"

	"github.com/Ullaakut/nmap/v3"
)

// NmapScanner represents an Nmap scanner
type NmapScanner struct {
	scanner *nmap.Scanner
}

// NewNmapScanner creates a new NmapScanner instance
func NewNmapScanner(ctx context.Context, targets string, iface string) (*NmapScanner, error) {
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
		nmap.WithFastMode(),
		nmap.WithScripts("vulners", "banner"),
	)
	if iface != "" {
		opts = append(opts, nmap.WithInterface(iface))
	}
	scanner, err := nmap.NewScanner(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create Nmap scanner: %w", err)
	}

	return &NmapScanner{scanner: scanner}, nil
}

// Run executes the Nmap scan and returns the results
func (ns *NmapScanner) Run() (*nmap.Run, error) {
	result, _, err := ns.scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to run Nmap scan: %w", err)
	}
	return result, nil
}
