package common

import (
	"fmt"
	"testing"
)

func TestNoDuplicatePortsInPorts(t *testing.T) {
	// Create a map to track port/protocol combinations
	seen := make(map[string][]string)

	for _, port := range Ports {
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
