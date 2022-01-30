package api

type Config struct {
	Routes []Route
}

type Route struct {
	Name  string `yaml:"name"`
	Nodes []Node `yaml:"nodes"`
}

type NodeType string

var (
	Process   NodeType = "process"
	Container NodeType = "container"
)

type TrafficType string

var (
	HTTP  TrafficType = "http"
	HTTPS TrafficType = "https"
)

type Node struct {
	Name    string       `yaml:"name"`
	Type    NodeType     `yaml:"type"`
	IP      string       `yaml:"ip,omitempty"`
	Iface   string       `yaml:"iface,omitempty"`
	Traffic *TrafficType `yaml:"traffic,omitempty"`
}
