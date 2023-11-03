// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64be || armbe || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64
// +build arm64be armbe mips mips64 mips64p32 ppc64 s390 s390x sparc sparc64

package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadEbpf returns the embedded CollectionSpec for ebpf.
func loadEbpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_EbpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load ebpf: %w", err)
	}

	return spec, err
}

// loadEbpfObjects loads ebpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *ebpfObjects
//     *ebpfPrograms
//     *ebpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadEbpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadEbpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// ebpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ebpfSpecs struct {
	ebpfProgramSpecs
	ebpfMapSpecs
}

// ebpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ebpfProgramSpecs struct {
	RedirectMarkedTraffic *ebpf.ProgramSpec `ebpf:"redirect_marked_traffic"`
	RedirectToIdps        *ebpf.ProgramSpec `ebpf:"redirect_to_idps"`
}

// ebpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type ebpfMapSpecs struct {
	IncomingPacketsPerfBuffer    *ebpf.MapSpec `ebpf:"incoming_packets_perf_buffer"`
	OriginalToProxyMap           *ebpf.MapSpec `ebpf:"original_to_proxy_map"`
	ProxyToOriginalMap           *ebpf.MapSpec `ebpf:"proxy_to_original_map"`
	RedirectInterfaceDestination *ebpf.MapSpec `ebpf:"redirect_interface_destination"`
}

// ebpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadEbpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type ebpfObjects struct {
	ebpfPrograms
	ebpfMaps
}

func (o *ebpfObjects) Close() error {
	return _EbpfClose(
		&o.ebpfPrograms,
		&o.ebpfMaps,
	)
}

// ebpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadEbpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type ebpfMaps struct {
	IncomingPacketsPerfBuffer    *ebpf.Map `ebpf:"incoming_packets_perf_buffer"`
	OriginalToProxyMap           *ebpf.Map `ebpf:"original_to_proxy_map"`
	ProxyToOriginalMap           *ebpf.Map `ebpf:"proxy_to_original_map"`
	RedirectInterfaceDestination *ebpf.Map `ebpf:"redirect_interface_destination"`
}

func (m *ebpfMaps) Close() error {
	return _EbpfClose(
		m.IncomingPacketsPerfBuffer,
		m.OriginalToProxyMap,
		m.ProxyToOriginalMap,
		m.RedirectInterfaceDestination,
	)
}

// ebpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadEbpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type ebpfPrograms struct {
	RedirectMarkedTraffic *ebpf.Program `ebpf:"redirect_marked_traffic"`
	RedirectToIdps        *ebpf.Program `ebpf:"redirect_to_idps"`
}

func (p *ebpfPrograms) Close() error {
	return _EbpfClose(
		p.RedirectMarkedTraffic,
		p.RedirectToIdps,
	)
}

func _EbpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed ebpf_bpfeb.o
var _EbpfBytes []byte
