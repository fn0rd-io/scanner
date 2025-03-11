package nmap

import (
	"fmt"
	"testing"
)

func TestPortsToString(t *testing.T) {
	tests := []struct {
		name     string
		ports    []NamedPort
		expected string
	}{
		{
			name: "TCP ports only",
			ports: []NamedPort{
				{Port: 80, Service: "HTTP", Protocol: TCP},
				{Port: 443, Service: "HTTPS", Protocol: TCP},
			},
			expected: "T:80,443",
		},
		{
			name: "UDP ports only",
			ports: []NamedPort{
				{Port: 53, Service: "DNS", Protocol: UDP},
				{Port: 161, Service: "SNMP", Protocol: UDP},
			},
			expected: "U:53,161",
		},
		{
			name: "Mixed TCP and UDP ports",
			ports: []NamedPort{
				{Port: 80, Service: "HTTP", Protocol: TCP},
				{Port: 53, Service: "DNS", Protocol: UDP},
			},
			expected: "T:80,U:53",
		},
		{
			name:     "Empty ports list",
			ports:    []NamedPort{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := portsToString(tt.ports)
			if result != tt.expected {
				t.Errorf("portsToString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNoDuplicatePortsInCommonPorts(t *testing.T) {
	// Create a map to track port/protocol combinations
	seen := make(map[string][]string)

	for _, port := range CommonPorts {
		// Track port by key with service name for better error reporting
		portKey := fmt.Sprintf("%d/%s", port.Port, port.Protocol)

		// Check if we've seen this port/protocol before
		if existing, ok := seen[portKey]; ok {
			t.Errorf("Duplicate port/protocol found: %d/%s appears multiple times with services %v and %s",
				port.Port,
				port.Protocol,
				existing,
				port.Service)
		}

		// Add this port to the seen map
		seen[portKey] = append(seen[portKey], port.Service)
	}
}
