package cmd

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"fwrouter/pkg/ebpf"
	"fwrouter/pkg/iface"
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
var ingressIdpsIface string
var egressIdpsIface string

func init() {
	runCmd.Flags().StringVar(&configFile, "config-file", "", "A config file containing the nodes for the route.")
	runCmd.Flags().StringVar(&ingressIdpsIface, "ingress-idps-iface", "idps0", "The ingress interface used by the IDPS system.")
	runCmd.Flags().StringVar(&egressIdpsIface, "egress-idps-iface", "idps1", "The egress interface used by the IDPS system.")
}

func runRouter(cmd *cobra.Command, args []string) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memory lock: %v", err)
	}

	parser := yaml.NewParser()
	cfg, err := parser.Parse(configFile)
	if err != nil {
		log.Fatalf("Failed to parse config file: '%s': %v", configFile, err)
	}

	defaultIface, err := iface.VerifyExists(defaultIface)
	if err != nil {
		log.Fatalf("Failed to verify egress interface '%s': %v", defaultIface, err)
	}
	defer iface.DetachIface(defaultIface)

	ingerssIdpsIface, err := iface.VerifyExists(ingressIdpsIface)
	if err != nil {
		log.Fatalf("Failed to verify egress interface '%s': %v", ingerssIdpsIface, err)
	}
	defer iface.DetachIface(ingerssIdpsIface)

	egressIdpsIface, err := iface.VerifyExists(ingressIdpsIface)
	if err != nil {
		log.Fatalf("Failed to verify egress interface '%s': %v", ingerssIdpsIface, err)
	}
	defer iface.DetachIface(ingerssIdpsIface)

	objsManager, err := ebpf.LoadObjects(defaultIface, egressIdpsIface)
	if err != nil {
		log.Fatalf("Failed to load eBPF program to kernel: %v", err)
	}

	err = objsManager.UpdateDefaultDestinationMap(defaultKey, ebpf.Destination{

		IngressIdpsIfaceIdx: uint32(ingerssIdpsIface.Attrs().Index),
	})
	if err != nil {
		log.Fatalf("failed to update destinations map: %v", err)
	}

	// Populate splicing map.
	for _, mapping := range cfg.InterfaceMappings {
		if err != nil {
			log.Fatalf("Failed to load socket mapping objects to kernel: %v", err)
		}
		defer objsManager.Detach()

		err = objsManager.UpdatePortMappingsMap(defaultKey, ebpf.SerializeMapping(mapping))
		if err != nil {
			log.Fatalf("Failed to populate port mapping: %v", err)
		}
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
