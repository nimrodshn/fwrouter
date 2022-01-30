package models

import "net"

type TrafficType string

var (
	HTTP  TrafficType = "http"
	HTTPS TrafficType = "https"
)

// Node represents a node in the packet route.
type Node struct {
	Name     string
	Ip       net.IP
	IfaceIdx int
	Traffic  TrafficType
}

// A route represents a list of nodes for packet flow through the host.
// the order of the nodes in the route dictates the order of packets through the host.
type Route struct {
	Name  string
	Nodes []*Node
}
