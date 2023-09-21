// This package contains lower level models used by the BPF program running in the kernel.
package ebpf

import (
	"encoding/binary"
	"fwrouter/pkg/models"
	"log"
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
	Cond    *Condition
	Queue   QueueType
	NextHop int32
}

func (t Transition) MarshalBinary() (data []byte, err error) {
	size := UINT_SIZE + UINT_SIZE + UINT_SIZE + UINT_SIZE
	res := make([]byte, size)

	if t.Cond != nil {
		binary.LittleEndian.PutUint32(res, uint32(t.Cond.Type))
		binary.LittleEndian.PutUint32(res[UINT_SIZE:], t.Cond.Value)
	}

	binary.LittleEndian.PutUint32(res[2*UINT_SIZE:], uint32(t.Queue))
	binary.LittleEndian.PutUint32(res[3*UINT_SIZE:], uint32(t.NextHop))
	log.Println(res)
	return res, nil
}

const UINT_SIZE = 4
const MAC_ADDR_SIZE = 6

func SerializeTransition(transition models.Transition) Transition {
	return Transition{
		Cond:    SerializeCondition(transition.Condition),
		Queue:   SerializeQueue(transition.Queue),
		NextHop: int32(transition.Action.NextInterface.InterfaceIdx),
	}
}

func SerializeCondition(condition *models.Condition) *Condition {
	if condition == nil {
		return nil
	}

	res := &Condition{}
	var conditionType ConditionType
	var value int
	switch condition.Type {
	case models.MarkCondition:
		conditionType = MARK
		value = condition.Match.(int)
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
