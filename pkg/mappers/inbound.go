package mappers

import (
	"fmt"
	"fwrouter/pkg/api"
	"fwrouter/pkg/iface"
	"fwrouter/pkg/models"
)

func MapConfig(config *api.Config) (*models.Config, error) {
	res := &models.Config{}

	conditionsMap := make(map[string]models.Condition)
	for _, condition := range config.Conditions {
		conditionToAdd := models.Condition{
			Name:  condition.Name,
			Type:  models.ConditionType(condition.Type),
			Value: condition.Value,
		}
		res.Conditions = append(res.Conditions, conditionToAdd)
		conditionsMap[condition.Name] = conditionToAdd
	}

	marksMap := make(map[string]models.Mark)
	for _, mark := range config.Marks {
		markToAdd := models.Mark{
			Name:  mark.Name,
			Value: mark.Value,
		}
		res.Marks = append(res.Marks, markToAdd)
		marksMap[mark.Name] = markToAdd
	}

	statesMap := make(map[string]models.State)
	for _, state := range config.States {
		var stateToAdd models.State
		stateToAdd.Name = state.Name
		// Verify the interface representing the state exists.
		iface, err := iface.VerifyExists(state.InterfaceName)
		if err != nil {
			return nil, err
		}
		stateToAdd.InterfaceName = state.InterfaceName
		stateToAdd.InterfaceIdx = iface.Attrs().Index
		stateToAdd.Transitions = make([]models.Transition, len(state.Transitions))
		statesMap[stateToAdd.Name] = stateToAdd
	}

	// Populate state transitions.
	for _, state := range config.States {
		for i, transition := range state.Transitions {
			var transitionToAdd models.Transition
			if _, ok := statesMap[transition.Action.NextState]; !ok {
				return nil, fmt.Errorf("failed to find state '%s', for transition '%s' in state '%s'", transition.Action.NextState, transition.Name, state.Name)
			}

			if transition.Action.Mark != "" {
				if mark, ok := marksMap[transition.Action.Mark]; ok {
					transitionToAdd.Action.Mark = mark
				} else {
					return nil, fmt.Errorf("failed to find mark '%s', for transition '%s' in state '%s'", transition.Action.Mark, transition.Name, state.Name)
				}
			}

			if transition.Condition != "" {
				if _, ok := conditionsMap[transition.Condition]; ok {
					transitionToAdd.Condition = conditionsMap[transition.Condition]
				} else {
					return nil, fmt.Errorf("failed to find condition '%s', for transition '%s' in state '%s'", transition.Condition, transition.Name, state.Name)
				}
			}

			nextState := statesMap[transition.Action.NextState]
			transitionToAdd.Action.NextState = &nextState
			transitionToAdd.Action.Queue = transition.Action.Queue
			transitionToAdd.Name = transition.Name
			transitionToAdd.Default = transition.Default
			statesMap[state.Name].Transitions[i] = transitionToAdd
		}
		res.States = append(res.States, statesMap[state.Name])
	}
	return res, nil
}
