package common

import "context"

type Scanner interface {
	New(ctx context.Context, targets string, iface string, udp bool) (Scanner, error)
	Run() ([]byte, error)
	Capabilities() []Protocol
}

var _scanners = make(map[string]Scanner)

// RegisterScanner registers a scanner implementation
func RegisterScanner(name string, scanner Scanner) {
	_scanners[name] = scanner
}

// GetScanner returns a scanner implementation by name
func GetScanner(name string) Scanner {
	return _scanners[name]
}
