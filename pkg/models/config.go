// A General note:
// Types in this package represent and intermidiate, easy to handle, structs that allow for easy handling and should be passed
// throughout the codebase and are detached from outward facing YAML / RESTful APIs or from the BPF "lower level" representation.
// This should make it easier to change the API or the BPF representations without having to change the entire codebase.
package models

// Config represents the internal transition table configuration, including the different
// states in the states machine and marks and conditions used to describe transitions from state to state.
type Config struct {
	Interfaces []Interface
}

// Condition represents a conditions which is used for a transition in the transitions table.
// It may or may not include a value which is used for matching (e.g Mark condition).
type Condition struct {
	Name  string
	Type  ConditionType
	Match interface{}
}

// A ConditionType is an enum for the different condition types used by transitions.
type ConditionType string

var (
	HTTPSTrafficCondition ConditionType = "https-traffic"
	MarkCondition         ConditionType = "mark"
	DefaultCondition      ConditionType = "default"
)

// A QueueType is an enum for the different queue types used by transitions.
type QueueType string

const (
	// QueueTypeIngress represents an ingress queue.
	QueueTypeIngress QueueType = "ingress"
	// QueueTypeEgress represents an egress queue.
	QueueTypeEgress QueueType = "egress"
)

// A Mark represents a mark which is either *attached* to a packet transitioning from on state to another in the state table,
// conversly, used to match against a packet by a specific Condition.
type Mark struct {
	Name  string
	Value uint32
}

// Represents a physical or virtual interface in the host machine.
type Interface struct {
	Name         string
	InterfaceIdx int
	Transition   *Transition
}

// A Transition represents a transition of packets from one State (interface) to another.
type Transition struct {
	Name      string
	Queue     QueueType
	Condition *Condition
	Action    Action
}

type Action struct {
	Queue         string
	NextInterface Interface
}
