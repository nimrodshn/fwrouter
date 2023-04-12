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

	// Load pre-compiled programs and maps into the kernel.
	objs, err := ebpf.LoadObjects()
	if err != nil {
		log.Fatalf("Failed to load eBPF objects to kernel: %v", err)
	}
	defer objs.Detach()

	parser := yaml.NewParser()
	rawConfigFile, err := parser.Parse(configFile)
	if err != nil {
		log.Fatalf("Failed to parse config file: '%s': %v", configFile, err)
	}

	cfg, err := mappers.MapConfig(rawConfigFile)
	if err != nil {
		log.Fatalf("Failed to map config file: '%s': %v", configFile, err)
	}

	err = populateTransitionsMapping(cfg, objs)
	if err != nil {
		log.Fatalf("Failed to populate transitions mapping: %v", err)
	}

	log.Println("Waiting for events..")
	<-setupSignalChannel()
	log.Println("Exiting...")
}

func populateTransitionsMapping(cfg *models.Config, objs *ebpf.Objects) error {
	for i, state := range cfg.States {
		if state.InterfaceName == defaultIface {
			for _, transition := range state.Transitions {
				objs.UpdateTransitionsMap(uint32(i), ebpf.SerializeTransition(transition))
			}
		}
	}
	return nil
}

func setupSignalChannel() <-chan os.Signal {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	return sigs
}
