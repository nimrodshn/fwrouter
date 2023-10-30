package api

type Config struct {
	InterfaceMappings []InterfaceMapping `yaml:"interface_mappings"`
}

type InterfaceMapping struct {
	// The name of the mapping.
	Name string `yaml:"name,omitempty"`
	// The lower bound of the mapping.
	LowPort uint32 `yaml:"low_port,omitempty"`
	// the higher bound of the mapping.
	HighPort uint32 `yaml:"high_port,omitempty"`
}
