package cmd

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"fwrouter/pkg/ebpf"
	"fwrouter/pkg/mappers"
	"fwrouter/pkg/models"
	"fwrouter/pkg/yaml"

	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
)

const defaultIface = "eth0"

var defaultKey uint32 = 0

var runCmd = cobra.Command{
	Use:   "run",
	Short: "Runs the in-kernel FW router",
	Run:   runRouter,
}

var configFile string

func init() {
	runCmd.Flags().StringVar(&configFile, "config-file", "", "A config file containing the nodes for the route.")
}

func runRouter(cmd *cobra.Command, args []string) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memory lock: %v", err)
	}

	parser := yaml.NewParser()
	rawConfigFile, err := parser.Parse(configFile)
	if err != nil {
		log.Fatalf("Failed to parse config file: '%s': %v", configFile, err)
	}

	cfg, err := mappers.MapConfig(rawConfigFile)
	if err != nil {
		log.Fatalf("Failed to map config file: '%s': %v", configFile, err)
	}

	// Load pre-compiled programs and populate maps.
	for _, state := range cfg.States {
		if state.Transitions == nil || len(state.Transitions) == 0 {
			continue
		}

		log.Printf("Loading eBPF objects for interface: %s", state.InterfaceName)
		objsManager, err := ebpf.LoadObjects(state.InterfaceName)
		if err != nil {
			log.Fatalf("Failed to load eBPF objects to kernel: %v", err)
		}
		defer objsManager.Detach()

		err = populateTransitionsMapping(state, objsManager)
		if err != nil {
			log.Fatalf("Failed to populate transitions mapping: %v", err)
		}
	}

	log.Println("Waiting for events..")
	<-setupSignalChannel()
	log.Println("Exiting...")
}

func populateTransitionsMapping(state models.State, objsManager ebpf.ObjectsManager) error {
	var err error
	var ingressCount uint32
	var egressCount uint32
	for _, transition := range state.Transitions {
		log.Printf("Populating transition for state '%s': %+v", state.Name, transition)
		switch transition.Queue {
		case models.QueueTypeIngress:
			if ingressCount, err = UpdateIngressTransition(transition, objsManager, ingressCount); err != nil {
				return err
			}
			err = objsManager.UpdateIngressTransitionsLengthMap(0, ingressCount)
			if err != nil {
				return err
			}
		case models.QueueTypeEgress:
			if egressCount, err = UpdateEgressTransition(transition, objsManager, egressCount); err != nil {
				return err
			}
			err = objsManager.UpdateEgressTransitionsLengthMap(0, egressCount)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func UpdateEgressTransition(transition models.Transition, objsManager ebpf.ObjectsManager, transitionIdx uint32) (uint32, error) {
	if transition.Default {
		var defaultKey uint32 = 0
		return transitionIdx, objsManager.UpdateEgressDefaultTransitionMap(defaultKey, ebpf.SerializeTransition(transition))
	}

	err := objsManager.UpdateEgressTransitionsMap(transitionIdx, ebpf.SerializeTransition(transition))
	if err != nil {
		return transitionIdx + 1, nil
	}
	return transitionIdx, nil
}

func UpdateIngressTransition(transition models.Transition, objsManager ebpf.ObjectsManager, transitionIdx uint32) (uint32, error) {
	if transition.Default {
		var defaultKey uint32 = 0
		return transitionIdx, objsManager.UpdateIngressDefaultTransitionMap(defaultKey, ebpf.SerializeTransition(transition))
	}

	err := objsManager.UpdateIngressTransitionsMap(transitionIdx, ebpf.SerializeTransition(transition))
	if err != nil {
		return transitionIdx + 1, nil
	}
	return transitionIdx, nil
}

func setupSignalChannel() <-chan os.Signal {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	return sigs
}
