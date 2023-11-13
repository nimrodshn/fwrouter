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
	redirectToIdpsQdisc         netlink.Qdisc
	redirectToIdpsIngressFilter netlink.Filter
	redirectToIdpsEgressFilter  netlink.Filter
	redirectMarkedTrafficQdisc  netlink.Qdisc
	redirectMarkedTrafficFilter netlink.Filter
}

// LoadObjects loads the eBPF program to kernel and attaches it to the newly created
// filter on the qdisc of the provided interface and returns a Manager providing API for managing and interacting with the eBPF program (via maps).
func LoadObjects(defaultIface, idpsEgressIface netlink.Link) (ObjectsManager, error) {
	objs := ebpfObjects{}
	if err := loadEbpfObjects(&objs, nil); err != nil {
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
		LinkIndex: defaultIface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	redirectToIdpsQdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(redirectToIdpsQdisc); err != nil {
		return nil, fmt.Errorf("failed to add qdisc: %v", err.Error())
	}

	redirectToIdpsIngressFilter, err := createFilterForRedirectToIdpsIngress(objs, defaultIface)
	if err != nil {
		return nil, err
	}

	redirectToIdpsEgressFilter, err := createFilterForRedirectToIdpsEgress(objs, defaultIface)
	if err != nil {
		return nil, err
	}

	err = netlink.FilterAdd(redirectToIdpsIngressFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to add filter err: %v", err.Error())
	}

	err = netlink.FilterAdd(redirectToIdpsEgressFilter)
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
		redirectToIdpsQdisc:         redirectToIdpsQdisc,
		redirectToIdpsIngressFilter: redirectToIdpsIngressFilter,
		redirectToIdpsEgressFilter:  redirectToIdpsEgressFilter,
		redirectMarkedTrafficQdisc:  redirectMarkedQdisc,
		redirectMarkedTrafficFilter: redirectMarkedFilter,
	}, nil
}

func (o *DefaultObjectsManager) Detach() error {
	if err := o.objects.Close(); err != nil {
		return fmt.Errorf("failed to remove eBPF program: %v", err)
	}
	if err := netlink.QdiscDel(o.redirectToIdpsQdisc); err != nil {
		return fmt.Errorf("failed to delete qdisc: %v", err)
	}
	if err := netlink.FilterDel(o.redirectToIdpsIngressFilter); err != nil {
		return fmt.Errorf("failed to delete filter %v: ", err)
	}
	if err := netlink.FilterDel(o.redirectToIdpsEgressFilter); err != nil {
		return fmt.Errorf("failed to delete filter %v: ", err)
	}
	if err := netlink.QdiscDel(o.redirectMarkedTrafficQdisc); err != nil {
		return fmt.Errorf("failed to delete qdisc: %v", err)
	}
	if err := netlink.FilterDel(o.redirectMarkedTrafficFilter); err != nil {
		return fmt.Errorf("failed to delete filter %v: ", err)
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

func createFilterForRedirectToIdpsIngress(objs ebpfObjects, defaultIface netlink.Link) (*netlink.BpfFilter, error) {
	redirectToIdpsIngressAttrs := netlink.FilterAttrs{
		LinkIndex: defaultIface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  redirectToIdpsIngressAttrs,
		Fd:           objs.RedirectToIdpsIngress.FD(),
		Name:         "redirect_to_idps_ingress",
		DirectAction: true,
	}

	return filter, nil
}

func createFilterForRedirectToIdpsEgress(objs ebpfObjects, defaultIface netlink.Link) (*netlink.BpfFilter, error) {
	redirectToIdpsEgressAttrs := netlink.FilterAttrs{
		LinkIndex: defaultIface.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  redirectToIdpsEgressAttrs,
		Fd:           objs.RedirectToIdpsEgress.FD(),
		Name:         "redirect_to_idps_egress",
		DirectAction: true,
	}

	return filter, nil
}

func (o *DefaultObjectsManager) UpdateRedirectInterfaceDestinationMap(key uint32, destination Destination) error {
	return o.objects.RedirectInterfaceDestination.Put(unsafe.Pointer(&key), destination)
}

func (o *DefaultObjectsManager) ReadIncomingPackets() (*perf.Reader, error) {
	return perf.NewReader(o.objects.IncomingPacketsPerfBuffer, 4096)
}
