// NOTE: The following comment is used to generate (using `go generate`) the eBPF object files and embed them into our code.
// Please, do not remove this line.  For more information see https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ../../bpf/bpf.c
package ebpf

import (
	"net"

	"github.com/vishvananda/netlink"
)

const defaultIface = "lo"

var nl netlink.Link

func LoadObjects() error {
	objs := ebpfObjects{}
	defer objs.Close()
	if err := loadEbpfObjects(&objs, nil); err != nil {
		return err
	}

	iface, err := net.InterfaceByName(defaultIface)
	if err != nil {
		return err
	}

	nl, err = netlink.LinkByIndex(iface.Index)
	if err != nil {
		return err
	}

	err = netlink.LinkSetXdpFd(nl, objs.Router.FD())
	if err != nil {
		return err
	}
	return nil
}

func Detach() error {
	return netlink.LinkSetXdpFd(nl, -1)
}
