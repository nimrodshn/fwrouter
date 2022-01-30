package registry

import (
	"fwrouter/pkg/api"
	"fwrouter/pkg/models"
	"net"
)

const (
	LoopBackIface = "lo"
)

var localHostIP = []byte{127, 0, 0, 1}

// RouteRegistry attempts to retrieve and register the list of routes from
// the config recieved by the user.
type RouteRegistry interface {
	Register(config *api.Config) ([]models.Route, error)
}

func NewRouteRegistry() RouteRegistry {
	return &NetRegistry{}
}

type NetRegistry struct{}

// An implementation of RouteRegistry using standard lib.
func (r *NetRegistry) Register(config *api.Config) ([]models.Route, error) {
	res := make([]models.Route, len(config.Routes))
	for i, route := range config.Routes {
		nodes := make([]*models.Node, len(route.Nodes))
		for j, node := range route.Nodes {
			registeredNode, err := r.registerNode(node)
			if err != nil {
				return nil, err
			}
			nodes[j] = registeredNode
		}
		res[i].Name = route.Name
		res[i].Nodes = nodes
	}
	return res, nil
}

func (r *NetRegistry) registerNode(node api.Node) (*models.Node, error) {
	var res *models.Node
	var err error
	switch node.Type {
	case api.Process:
		res, err = r.registerProcessNode(node)
		if err != nil {
			return nil, err
		}
	case api.Container:
		res, err = r.registerContainerNode(node)
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

// Attempts to register a Node of type Container.
func (r *NetRegistry) registerContainerNode(node api.Node) (*models.Node, error) {
	return &models.Node{}, nil
}

// Attempts to register a Node of type Process.
func (r *NetRegistry) registerProcessNode(node api.Node) (*models.Node, error) {
	var IfaceIdx int
	var IP net.IP
	res := &models.Node{
		Name: node.Name,
	}

	if node.Iface == "" {
		loopBackIface, err := net.InterfaceByName(LoopBackIface)
		if err != nil {
			return nil, err
		}
		IfaceIdx = loopBackIface.Index
	} else {
		iface, err := net.InterfaceByName(node.Iface)
		if err != nil {
			return nil, err
		}
		IfaceIdx = iface.Index
	}

	if node.IP == "" {
		IP = localHostIP
	} else {
		IP = net.ParseIP(node.IP)
	}

	if node.Traffic == nil {
		res.Traffic = models.HTTP
	} else {
		res.Traffic = models.TrafficType(*node.Traffic)
	}

	res.IfaceIdx = IfaceIdx
	res.Ip = IP
	return res, nil
}
