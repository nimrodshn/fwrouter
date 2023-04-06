package api

type Config struct {
	States     []State
	Marks      []Mark
	Conditions []Condition
}

type Condition struct {
	// The name of the condition.
	Name string
	// The type of the condition.
	Type ConditionType
	// The value to be matched against.
	Value interface{}
}

type ConditionType string

var (
	L7ProtocolCondition ConditionType = "l7-protocol"
	MarkCondition       ConditionType = "mark"
)

type Mark struct {
	// The name of the mark.
	Name string
	// The value of the mark.
	Value uint32
}

type State struct {
	// The name of the state (e.g "idps", "envoy", "eth0", etc.).
	Name string `yaml:"name"`
	// The name of the interface to be used for this state.
	InterfaceName string `yaml:"interface"`
	// The set of transitions for this state.
	Transitions []Transition `yaml:"transitions"`
}

type Transition struct {
	// The name of the transition.
	Name string
	// The condition name used to match this transition.
	Condition string `yaml:"condition"`
	// The queue to be used for the next interface, represented by state in the state table.
	Queue string `yaml:"ip,omitempty"`
	// The name of the next state.
	Next string `yaml:"next"`
	// The mark to be set on the packet.
	Mark string `yaml:"condition,omitempty"`
}
