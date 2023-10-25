package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"fwrouter/pkg/ebpf"
	"fwrouter/pkg/yaml"

	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
)

const connHost = "localhost"
const connType = "tcp"
const defaultIface = "eth0"
const defaultPort = 3000

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
	cfg, err := parser.Parse(configFile)
	if err != nil {
		log.Fatalf("Failed to parse config file: '%s': %v", configFile, err)
	}

	objsManager, err := ebpf.LoadObjects(defaultIface)

	go buildDefaultServer(defaultPort, objsManager)

	// Load pre-compiled programs and populate maps.
	for _, mapping := range cfg.SocketMappings {
		if err != nil {
			log.Fatalf("Failed to load eBPF objects to kernel: %v", err)
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

func buildDefaultServer(port int, objsManager ebpf.ObjectsManager) {
	listenAddress := fmt.Sprintf("%s:%d", connHost, defaultPort)
	l, err := net.Listen(connType, listenAddress)
	if err != nil {
		log.Fatalf("failed to listen on port %d: %s", port, err)
	}

	defer func() {
		err := l.Close()
		if err != nil {
			log.Fatalf("failed to close socket: %s", err)
		}
	}()
	log.Printf("listening on address: %s", listenAddress)

	for {
		// accept
		conn, err := l.Accept()
		if err != nil {
			log.Fatalf("error accepting: %s", err)
		}

		// retrieve copy of connection file descriptor
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			log.Fatalf("failed to cast connection to TCP connection")
		}

		f, err := tcpConn.File()
		if err != nil {
			log.Fatalf("failed to retrieve copy of the underlying TCP connection file")
		}
		d := f.Fd()

		objsManager.UpdateDefaultSocketMap(defaultKey, ebpf.Socket{FileDescriptor: d})
	}
}
