// This package contains lower level models used by the BPF program running in the kernel.
package ebpf

import "fwrouter/pkg/api"

type PortMapping struct {
	LowPort  uint32
	HighPort uint32
}

func SerializeMapping(mapping api.InterfaceMapping) PortMapping {
	return PortMapping{
		LowPort:  mapping.LowPort,
		HighPort: mapping.HighPort,
	}
}

// Represents an interface for the bpf program to redirect.
type Destination struct {
	DefaultIfaceIdx     uint32
	IngressIdpsIfaceIdx uint32
}
