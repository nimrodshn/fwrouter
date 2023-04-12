// A General note:
// Types in this package represent and intermidiate, easy to handle, structs that allow for easy handling and should be passed
// throughout the codebase and are detached from outward facing YAML / RESTful APIs or from the BPF "lower level" representation.
// This should make it easier to change the API or the BPF representations without having to change the entire codebase.
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
	HTTPSTrafficCondition ConditionType = "https-traffic"
	MarkCondition         ConditionType = "mark"
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
