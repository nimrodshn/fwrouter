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

		err = populateTransitionsMapping(cfg, objsManager)
		if err != nil {
			log.Fatalf("Failed to populate transitions mapping: %v", err)
		}
	}

	log.Println("Waiting for events..")
	<-setupSignalChannel()
	log.Println("Exiting...")
}

func populateTransitionsMapping(cfg *models.Config, objsManager ebpf.ObjectsManager) error {
	for _, state := range cfg.States {
		var idx uint32 = 0
		for _, transition := range state.Transitions {
			if transition.Default {
				var defaultKey uint32 = 0
				err := objsManager.UpdateDefaultTransitionMap(defaultKey, ebpf.SerializeTransition(transition))
				if err != nil {
					return err
				}
				continue
			}

			err := objsManager.UpdateTransitionsMap(idx, ebpf.SerializeTransition(transition))
			if err != nil {
				return err
			}

			err = objsManager.UpdateTransitionsLengthMap(0, idx)
			if err != nil {
				return err
			}
			idx++
		}
	}
	return nil
}

func setupSignalChannel() <-chan os.Signal {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	return sigs
}
