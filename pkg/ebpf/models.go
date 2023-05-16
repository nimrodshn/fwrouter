// This package contains lower level models used by the BPF program running in the kernel.
package ebpf

import (
	"fwrouter/pkg/models"
)

type ConditionType uint32

const (
	L7_PROTOCOL_HTTPS ConditionType = iota
	MARK
	DEFAULT
)

type QueueType uint32

const (
	INGRESS QueueType = iota
	EGRESS
)

// Represents a transition for the bpf to use in routing traffic.
type Condition struct {
	Type  ConditionType
	Value uint32
}

// Represents a transition for the bpf program to oversee.
type Transition struct {
	Cond    Condition
	Queue   QueueType
	Mark    uint32
	NextHop uint32
}

const UINT_SIZE = 4
const MAC_ADDR_SIZE = 6

func SerializeTransition(transition models.Transition) Transition {
	return Transition{
		Cond:    SerializeCondition(transition.Condition),
		Queue:   SerializeQueue(transition.Queue),
		Mark:    transition.Action.Mark.Value,
		NextHop: uint32(transition.Action.NextState.InterfaceIdx),
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
	default:
		conditionType = DEFAULT
	}

	res.Type = conditionType
	res.Value = uint32(value)
	return res
}

func SerializeQueue(queue models.QueueType) QueueType {
	switch queue {
	case models.QueueTypeEgress:
		return EGRESS
	default:
		return INGRESS
	}
}
