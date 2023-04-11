package models

type Config struct {
	States     []State
	Marks      []Mark
	Conditions []Condition
}

type Condition struct {
	Name  string
	Type  ConditionType
	Value interface{}
}

type ConditionType string

var (
	L7ProtocolCondition ConditionType = "l7-protocol"
	MarkCondition       ConditionType = "mark"
)

type Mark struct {
	Name  string
	Value uint32
}

type State struct {
	Name          string
	InterfaceName string
	InterfaceIdx  int
	Transitions   []Transition
}

type Transition struct {
	Name      string
	Condition Condition
	Queue     string
	Next      *State
	Mark      Mark
}
