// NOTE: The following comment is used to generate (using `go generate`) the eBPF object files and embed them into our code.
// Please, do not remove this line.  For more information see https://pkg.go.dev/github.com/cilium/ebpf/cmd/bpf2go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go ebpf ../../bpf/bpf.c
package ebpf

import (
	"fmt"
	"fwrouter/pkg/models"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const defaultIface = "eth0"

type ConditionType uint32

const (
	L7_PROTOCOL_HTTPS ConditionType = iota
	MARK
)

// Represents a transition for the bpf to use in routing traffic.
type Condition struct {
	Name  [32]byte
	Type  ConditionType
	Value uint32
}

// Represents a transition for the bpf program to oversee.
type Transition struct {
	Name    [32]byte
	Cond    Condition
	Mark    uint32
	NextHop uint32
}

type Objects struct {
	objects ebpfObjects
	filter  netlink.Filter
	qdisc   netlink.Qdisc
}

func LoadObjects() (*Objects, error) {
	objs := ebpfObjects{}
	defer objs.Close()
	if err := loadEbpfObjects(&objs, nil); err != nil {
		return nil, err
	}

	iface, err := net.InterfaceByName(defaultIface)
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

	filterattrs := netlink.FilterAttrs{
		LinkIndex: nl.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  filterattrs,
		Fd:           objs.TcIngress.FD(),
		Name:         "tc_ingress",
		DirectAction: true,
	}

	err = netlink.FilterAdd(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to add filter err: %v", err.Error())
	}

	return &Objects{
		objects: objs,
		filter:  filter,
		qdisc:   qdisc,
	}, nil
}

func (o *Objects) Detach() error {
	err := netlink.FilterDel(o.filter)
	if err != nil {
		return fmt.Errorf("failed to delete filter %v: ", err)
	}
	if err := netlink.QdiscDel(o.qdisc); err != nil {
		return fmt.Errorf("failed to delete qdisc: %v", err)
	}
	return nil
}

func (o *Objects) UpdateTransitionsMap(key uint32, transition Transition) error {
	return o.objects.TransitionsMaps.Put(key, transition)
}

func SerializeTransition(transition models.Transition) Transition {
	return Transition{
		Name:    [32]byte{},
		Cond:    SerializeCondition(transition.Condition),
		Mark:    uint32(transition.Mark.Value),
		NextHop: uint32(transition.Next.InterfaceIdx),
	}
}

func SerializeCondition(condition models.Condition) Condition {
	var res Condition
	var conditionType ConditionType
	var value uint32
	switch condition.Type {
	case models.MarkCondition:
		conditionType = MARK
		value = condition.Value.(uint32)
	case models.HTTPSTrafficCondition:
		conditionType = L7_PROTOCOL_HTTPS
	}

	copy(res.Name[:], []byte(condition.Name))
	res.Type = conditionType
	res.Value = uint32(value)
	return res
}
