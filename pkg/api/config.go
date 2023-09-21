package api

type Config struct {
	Interfaces []Interface `yaml:"interfaces"`
}

type Condition struct {
	// The name of the condition.
	Name string
	// The type of the condition.
	Type ConditionType
	// The value to be matched against.
	Match interface{}
}

type ConditionType string

var (
	L7ProtocolCondition ConditionType = "l7-protocol"
	MarkCondition       ConditionType = "mark"
	DefaultCondition    ConditionType = "default"
)

type Mark struct {
	// The name of the mark.
	Name string
	// The value of the mark.
	Value uint32
}

type Interface struct {
	// The name of the interface (e.g "eth0", etc.).
	Name string `yaml:"name"`
	// The transitions to apply to this interface.
	Transition *Transition `yaml:"transition,omitempty"`
}

type Transition struct {
	// The name of the transition.
	Name string `yaml:"name"`
	// The condition name used to match this transition.
	Condition *Condition `yaml:"condition,omitempty"`
	// The action to be taken when this transition is matched.
	Action Action `yaml:"action"`
	// Queue to be used for this transition.
	Queue string `yaml:"queue"`
}

type Action struct {
	// The name of the next state.
	NextInterface string `yaml:"next-interface"`
	// The queue to be used for the next interface, represented by state in the state table.
	Queue string `yaml:"queue"`
}
