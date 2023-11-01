// This package contains lower level models used by the BPF program running in the kernel.
package ebpf

// Represents an the interface destinations for the bpf program to redirect.
type Destination struct {
	DefaultIfaceIdx     uint32
	IngressIdpsIfaceIdx uint32
}

// L4 Packet passed.
type Packet struct {
	SourcePort      uint16
	DestinationPort uint16
	SourceIp        uint32
	DestinationIp   uint32
}
