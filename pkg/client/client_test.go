package client

import (
	"os/exec"
	"testing"

	coordinatorv1 "github.com/fn0rd-io/protobuf/coordinator/v1"
	"github.com/stretchr/testify/assert"
)

func TestDetermineCapabilities(t *testing.T) {
	// First check if nmap is actually available on this system
	// This helps make the test more useful by providing context in the output
	nmapAvailable := isNmapAvailable()
	t.Logf("Nmap available on test system: %v", nmapAvailable)

	// Call the actual function
	c, _ := NewClient(DefaultConfig())
	capabilities := c.determineCapabilities()

	// Basic validation - make sure the return value is valid
	assert.NotNil(t, capabilities, "Should return a non-nil slice")

	// Check if returned capabilities match the actual system state
	if nmapAvailable {
		t.Log("Nmap is available, expecting capabilities")

		// At minimum, CAPABILITY_NMAP should be present if nmap binary is found
		hasNmap := false
		for _, c := range capabilities {
			if c == coordinatorv1.Capability_CAPABILITY_NMAP {
				hasNmap = true
				break
			}
		}
		assert.True(t, hasNmap, "Expected CAPABILITY_NMAP to be reported when nmap is available")

		// Note: We don't assert CAPABILITY_NMAP_FULL because even with nmap available,
		// it might fail to run in some testing environments
	} else {
		t.Log("Nmap is not available, expecting no capabilities")
		assert.Empty(t, capabilities, "Expected no capabilities when nmap is not available")
	}
}

// Helper function to check if nmap is available on the system
func isNmapAvailable() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

// TestDetermineCapabilitiesOutput verifies the function's output structure
func TestDetermineCapabilitiesOutput(t *testing.T) {
	// This test focuses on the function's structure and return type
	c, _ := NewClient(DefaultConfig())
	capabilities := c.determineCapabilities()

	// Check returned slice type and contents
	for _, cap := range capabilities {
		// Verify each capability is a valid enum value
		assert.Contains(t, []coordinatorv1.Capability{
			coordinatorv1.Capability_CAPABILITY_NMAP,
			coordinatorv1.Capability_CAPABILITY_NMAP_FULL,
		}, cap, "Capability should be a valid enum value")
	}
}
