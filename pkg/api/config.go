package api

type Config struct {
	SocketMappings []SocketMapping `yaml:"socket_mappings"`
}

type SocketMapping struct {
	// The name of the mapping.
	Name string `yaml:"ports,omitempty"`
	// The lower bound of the mapping.
	LowPort uint32 `yaml:"low_port,omitempty"`
	// the higher bound of the mapping.
	HighPort uint32 `yaml:"high_port,omitempty"`
}
