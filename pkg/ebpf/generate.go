// NOTE: The following comment is used to generate (using `go generate`) the eBPF object files and embed them into our code.
// Please, do not remove this line.  For more information see https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ../../bpf/bpf.c
package ebpf

import (
	"fmt"
	"log"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// A manager exposing API for handling our eBPF loaded maps and programs.
type ObjectsManager interface {
	Detach() error
	UpdateIngressTransitionsMap(key uint32, transition Transition) error
	UpdateEgressTransitionsMap(key uint32, transition Transition) error
}

type DefaultObjectsManager struct {
	objects       ebpfObjects
	ingressFilter netlink.Filter
	egressFilter  netlink.Filter
	qdisc         netlink.Qdisc
}

// LoadObjects loads the eBPF program to kernel and attaches it to the newly created
// filter on the qdisc of the provided interface and returns a Manager providing API for managing and interacting with the eBPF program (via maps).
func LoadObjects(ifac string) (ObjectsManager, error) {
	objs := ebpfObjects{}
	if err := loadEbpfObjects(&objs, nil); err != nil {
		return nil, err
	}

	iface, err := net.InterfaceByName(ifac)
	if err != nil {
		return nil, err
	}

	nl, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		return nil, err
	}

	// Create a 'clsact' qdisc and attach it to our
	// source interface. This qdisc will than be used
	// to attach our bpf program on its ingress hook.
	// This qdisc is a dummy providing the necessary ingress/egress
	// hook points for our bpf program.
	// For more information see the following articles: https://docs.cilium.io/en/latest/bpf/progtypes/#tc-traffic-control
	// as well as https://lwn.net/Articles/671458/
	attrs := netlink.QdiscAttrs{
		LinkIndex: nl.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		return nil, fmt.Errorf("failed to add qdisc: %v", err.Error())
	}

	filterIngressAttrs := netlink.FilterAttrs{
		LinkIndex: nl.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	filterEgressAttrs := netlink.FilterAttrs{
		LinkIndex: nl.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	filterIngress := &netlink.BpfFilter{
		FilterAttrs:  filterIngressAttrs,
		Fd:           objs.TcIngress.FD(),
		Name:         "tc_ingress",
		DirectAction: true,
	}

	err = netlink.FilterAdd(filterIngress)
	if err != nil {
		return nil, fmt.Errorf("failed to add filter err: %v", err.Error())
	}

	filterEgress := &netlink.BpfFilter{
		FilterAttrs:  filterEgressAttrs,
		Fd:           objs.TcEgress.FD(),
		Name:         "tc_egress",
		DirectAction: true,
	}

	err = netlink.FilterAdd(filterEgress)
	if err != nil {
		return nil, fmt.Errorf("failed to add filter err: %v", err.Error())
	}

	return &DefaultObjectsManager{
		objects:       objs,
		ingressFilter: filterIngress,
		egressFilter:  filterEgress,
		qdisc:         qdisc,
	}, nil
}

func (o *DefaultObjectsManager) Detach() error {
	if err := o.objects.Close(); err != nil {
		return fmt.Errorf("failed to remove eBPF program: %v", err)
	}
	if err := netlink.FilterDel(o.ingressFilter); err != nil {
		return fmt.Errorf("failed to delete filter %v: ", err)
	}
	if err := netlink.FilterDel(o.egressFilter); err != nil {
		return fmt.Errorf("failed to delete filter %v: ", err)
	}
	if err := netlink.QdiscDel(o.qdisc); err != nil {
		return fmt.Errorf("failed to delete qdisc: %v", err)
	}
	return nil
}

func (o *DefaultObjectsManager) UpdateIngressTransitionsMap(key uint32, transition Transition) error {
	log.Printf("Updating ingress transition map with key '%d': %+v", key, transition)
	return o.objects.IngressTransitions.Put(key, transition)
}

func (o *DefaultObjectsManager) UpdateEgressTransitionsMap(key uint32, transition Transition) error {
	log.Printf("Updating egress transition map with key '%d': %+v", key, transition)
	return o.objects.EgressTransitions.Put(key, transition)
}
