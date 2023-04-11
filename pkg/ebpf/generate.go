// NOTE: The following comment is used to generate (using `go generate`) the eBPF object files and embed them into our code.
// Please, do not remove this line.  For more information see https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ../../bpf/bpf.c
package ebpf

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const defaultIface = "lo"

var filter netlink.Filter
var qdisc netlink.Qdisc

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

	nl, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return err
	}

	// Create a 'clsact' qdisc and attach it to our
	// source interface. This qdisc will than be used
	// to attach our bpf program on its ingress hook.
	// This qdisc is a dummy providing the necessary ingress/egress
	// hook points for our bpf program.
	// For more information please see: https://docs.cilium.io/en/latest/bpf/progtypes/#tc-traffic-control
	attrs := netlink.QdiscAttrs{
		LinkIndex: nl.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc = &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		return fmt.Errorf("failed to add qdisc: %v", err.Error())
	}

	filterattrs := netlink.FilterAttrs{
		LinkIndex: nl.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	filter = &netlink.BpfFilter{
		FilterAttrs:  filterattrs,
		Fd:           objs.TcIngress.FD(),
		Name:         "tc_ingress",
		DirectAction: true,
	}

	err = netlink.FilterAdd(filter)
	if err != nil {
		return fmt.Errorf("failed to add filter err: %v", err.Error())
	}
	return nil
}

func Detach() error {
	err := netlink.FilterDel(filter)
	if err != nil {
		return fmt.Errorf("failed to delete filter %v: ", err)
	}
	if err := netlink.QdiscDel(qdisc); err != nil {
		return fmt.Errorf("failed to delete qdisc: %v", err)
	}
	return nil
}
