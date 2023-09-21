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

	log.Println("Config: ", cfg)

	// Load pre-compiled programs and populate maps.
	for _, iface := range cfg.Interfaces {
		log.Printf("Loading eBPF objects for interface: %s", iface.Name)
		objsManager, err := ebpf.LoadObjects(iface.Name)
		if err != nil {
			log.Fatalf("Failed to load eBPF objects to kernel: %v", err)
		}
		defer objsManager.Detach()

		err = populateTransitionMapping(iface, objsManager)
		if err != nil {
			log.Fatalf("Failed to populate transitions mapping: %v", err)
		}
	}

	log.Println("Waiting for events..")
	<-setupSignalChannel()
	log.Println("Exiting...")
}

func populateTransitionMapping(iface models.Interface, objsManager ebpf.ObjectsManager) error {
	if iface.Transition == nil {
		return nil
	}

	switch iface.Transition.Queue {
	case models.QueueTypeIngress:
		if err := objsManager.UpdateIngressTransitionsMap(defaultKey, ebpf.SerializeTransition(*iface.Transition)); err != nil {
			return err
		}
	case models.QueueTypeEgress:
		if err := objsManager.UpdateEgressTransitionsMap(defaultKey, ebpf.SerializeTransition(*iface.Transition)); err != nil {
			return err
		}
	}

	return nil
}

func setupSignalChannel() <-chan os.Signal {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	return sigs
}
