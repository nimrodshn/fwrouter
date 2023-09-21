package mappers

import (
	"fwrouter/pkg/api"
	"fwrouter/pkg/iface"
	"fwrouter/pkg/models"
)

func MapConfig(config *api.Config) (*models.Config, error) {
	res := &models.Config{}

	interfacesMap := make(map[string]models.Interface)
	for _, intrfce := range config.Interfaces {
		var ifaceToAdd models.Interface
		ifaceToAdd.Name = intrfce.Name
		// Verify the interface representing the state exists.
		iface, err := iface.VerifyExists(intrfce.Name)
		if err != nil {
			return nil, err
		}
		ifaceToAdd.InterfaceIdx = iface.Attrs().Index

		if intrfce.Transition != nil {
			ifaceToAdd.Transition = &models.Transition{}
			ifaceToAdd.Transition.Name = intrfce.Transition.Name
			if intrfce.Transition.Condition != nil {
				ifaceToAdd.Transition.Condition = &models.Condition{}
				ifaceToAdd.Transition.Condition.Name = intrfce.Transition.Condition.Name
				ifaceToAdd.Transition.Condition.Type = models.ConditionType(intrfce.Transition.Condition.Type)
				ifaceToAdd.Transition.Condition.Match = intrfce.Transition.Condition.Match
				// Default to ingress queue if no queue is specified.
				if intrfce.Transition.Queue == "" {
					ifaceToAdd.Transition.Queue = models.QueueTypeIngress
				} else {
					switch intrfce.Transition.Queue {
					case "ingress":
						ifaceToAdd.Transition.Queue = models.QueueTypeIngress
					case "egress":
						ifaceToAdd.Transition.Queue = models.QueueTypeEgress
					default:
						ifaceToAdd.Transition.Queue = models.QueueTypeIngress
					}
				}
				ifaceToAdd.Transition.Action.NextInterface.Name = intrfce.Transition.Action.NextInterface
			}
		}

		interfacesMap[ifaceToAdd.Name] = ifaceToAdd
	}

	for _, intrfce := range interfacesMap {
		if intrfce.Transition == nil {
			continue
		}
		nextInterface := interfacesMap[intrfce.Transition.Action.NextInterface.Name]
		intrfce.Transition.Action.NextInterface = nextInterface
		res.Interfaces = append(res.Interfaces, intrfce)
	}
	return res, nil
}
