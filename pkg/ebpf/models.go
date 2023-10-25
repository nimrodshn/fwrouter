// This package contains lower level models used by the BPF program running in the kernel.
package ebpf

import "fwrouter/pkg/api"

type PortMapping struct {
	LowPort  uint32
	HighPort uint32
}

func SerializeMapping(mapping api.SocketMapping) PortMapping {
	return PortMapping{
		LowPort:  mapping.LowPort,
		HighPort: mapping.HighPort,
	}
}

// Represents a socket for the bpf program to oversee.
type Socket struct {
	FileDescriptor uintptr
}
