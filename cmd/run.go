package cmd

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"fwrouter/pkg/config"
	"fwrouter/pkg/ebpf"
	"fwrouter/pkg/registry"

	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
)

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
	if err := ebpf.LoadObjects(); err != nil {
		log.Fatalf("Failed to load eBPF objects to kernel: %v", err)
	}
	defer ebpf.Detach()

	parser := config.NewParser()
	cfg, err := parser.Parse(configFile)
	if err != nil {
		log.Fatalf("Failed to parse config file: '%s': %v", configFile, err)
	}

	// Attempt to register the routes passed in the config file.
	// Register will validate that the nodes exist and that the routes
	// do not collide with one another in a manner which will be interpretable
	// by the router.
	reg := registry.NewRouteRegistry()
	_, err = reg.Register(cfg)
	if err != nil {
		log.Fatalf("Failed to register the recieved routes: %v", err)
	}

	log.Println("Waiting for events..")
	<-setupSignalChannel()
	log.Println("Exiting...")
}

func setupSignalChannel() <-chan os.Signal {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	return sigs
}
