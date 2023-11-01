// NOTE: The following comment is used to generate (using `go generate`) the eBPF object files and embed them into our code.
// Please, do not remove this line.  For more information see https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ../../bpf/bpf.c
package ebpf

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// A manager exposing API for handling our eBPF loaded maps and programs.
type ObjectsManager interface {
	Detach() error
	UpdateRedirectInterfaceDestinationMap(key uint32, destination Destination) error
	ReadIncomingPackets() (*perf.Reader, error)
}

type DefaultObjectsManager struct {
	objects                     ebpfObjects
	redirectToIdpsFilter        netlink.Filter
	redirectToIdpsQdisc         netlink.Qdisc
	redirectMarkedTrafficFilter netlink.Filter
	redirectMarkedTrafficQdisc  netlink.Qdisc
}

// LoadObjects loads the eBPF program to kernel and attaches it to the newly created
// filter on the qdisc of the provided interface and returns a Manager providing API for managing and interacting with the eBPF program (via maps).
func LoadObjects(defaultIface, idpsEgressIface netlink.Link) (ObjectsManager, error) {
	objs := ebpfObjects{}
	if err := loadEbpfObjects(&objs, nil); err != nil {
		return nil, err
	}

	redirectToIdpsFilter, redirectToIdpsQdisc, err := createQdiscForRedirectToIdps(objs, defaultIface)
	if err != nil {
		return nil, err
	}

	err = netlink.FilterAdd(redirectToIdpsFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to add filter err: %v", err.Error())
	}

	redirectMarkedFilter, redirectMarkedQdisc, err := createQdiscForRedirectMarkedTraffic(objs, idpsEgressIface)
	if err != nil {
		return nil, err
	}

	err = netlink.FilterAdd(redirectMarkedFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to add filter err: %v", err.Error())
	}

	return &DefaultObjectsManager{
		objects:                     objs,
		redirectToIdpsFilter:        redirectToIdpsFilter,
		redirectToIdpsQdisc:         redirectToIdpsQdisc,
		redirectMarkedTrafficFilter: redirectMarkedFilter,
		redirectMarkedTrafficQdisc:  redirectMarkedQdisc,
	}, nil
}

func (o *DefaultObjectsManager) Detach() error {
	if err := o.objects.Close(); err != nil {
		return fmt.Errorf("failed to remove eBPF program: %v", err)
	}
	if err := netlink.FilterDel(o.redirectToIdpsFilter); err != nil {
		return fmt.Errorf("failed to delete filter %v: ", err)
	}
	if err := netlink.QdiscDel(o.redirectToIdpsQdisc); err != nil {
		return fmt.Errorf("failed to delete qdisc: %v", err)
	}
	if err := netlink.FilterDel(o.redirectMarkedTrafficFilter); err != nil {
		return fmt.Errorf("failed to delete filter %v: ", err)
	}
	if err := netlink.QdiscDel(o.redirectToIdpsQdisc); err != nil {
		return fmt.Errorf("failed to delete qdisc: %v", err)
	}
	return nil
}

func createQdiscForRedirectMarkedTraffic(objs ebpfObjects, idpsEgressIface netlink.Link) (*netlink.BpfFilter, *netlink.GenericQdisc, error) {
	// Create a 'clsact' qdisc and attach it to our
	// source interface. This qdisc will than be used
	// to attach our bpf program on its ingress hook.
	// This qdisc is a dummy providing the necessary ingress/egress
	// hook points for our bpf program.
	// For more information see the following articles: https://docs.cilium.io/en/latest/bpf/progtypes/#tc-traffic-control
	// as well as https://lwn.net/Articles/671458/
	attrs := netlink.QdiscAttrs{
		LinkIndex: idpsEgressIface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		return nil, nil, fmt.Errorf("failed to add qdisc: %v", err.Error())
	}

	redirectToIdpsIngressAttrs := netlink.FilterAttrs{
		LinkIndex: idpsEgressIface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  redirectToIdpsIngressAttrs,
		Fd:           objs.RedirectMarkedTraffic.FD(),
		Name:         "redirect_marked_traffic",
		DirectAction: true,
	}

	return filter, qdisc, nil
}

func createQdiscForRedirectToIdps(objs ebpfObjects, defaultIface netlink.Link) (*netlink.BpfFilter, *netlink.GenericQdisc, error) {
	// Create a 'clsact' qdisc and attach it to our
	// source interface. This qdisc will than be used
	// to attach our bpf program on its ingress hook.
	// This qdisc is a dummy providing the necessary ingress/egress
	// hook points for our bpf program.
	// For more information see the following articles: https://docs.cilium.io/en/latest/bpf/progtypes/#tc-traffic-control
	// as well as https://lwn.net/Articles/671458/
	attrs := netlink.QdiscAttrs{
		LinkIndex: defaultIface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		return nil, nil, fmt.Errorf("failed to add qdisc: %v", err.Error())
	}

	redirectToIdpsIngressAttrs := netlink.FilterAttrs{
		LinkIndex: defaultIface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  redirectToIdpsIngressAttrs,
		Fd:           objs.RedirectToIdps.FD(),
		Name:         "redirect_to_idps",
		DirectAction: true,
	}

	return filter, qdisc, nil
}

func (o *DefaultObjectsManager) UpdateRedirectInterfaceDestinationMap(key uint32, destination Destination) error {
	return o.objects.RedirectInterfaceDestination.Put(unsafe.Pointer(&key), destination)
}

func (o *DefaultObjectsManager) ReadIncomingPackets() (*perf.Reader, error) {
	return perf.NewReader(o.objects.IncomingPacketsPerfBuffer, 4096)
}
