package nmap

import (
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
