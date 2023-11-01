package cmd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"fwrouter/pkg/ebpf"
	"fwrouter/pkg/iface"

	"github.com/cilium/ebpf/perf"
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

var ingressIdpsIface string
var egressIdpsIface string

func init() {
	runCmd.Flags().StringVar(&ingressIdpsIface, "ingress-idps-iface", "idps0", "The ingress interface used by the IDPS system.")
	runCmd.Flags().StringVar(&egressIdpsIface, "egress-idps-iface", "idps1", "The egress interface used by the IDPS system.")
}

func runRouter(cmd *cobra.Command, args []string) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memory lock: %v", err)
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
	defer objsManager.Detach()

	err = objsManager.UpdateRedirectInterfaceDestinationMap(defaultKey, ebpf.Destination{
		DefaultIfaceIdx:     uint32(defaultIface.Attrs().Index),
		IngressIdpsIfaceIdx: uint32(ingerssIdpsIface.Attrs().Index),
	})
	if err != nil {
		log.Fatalf("failed to update destinations map: %v", err)
	}

	reader, err := objsManager.ReadIncomingPackets()
	if err != nil {
		log.Fatalf("failed to obtain reader for incoming packets: %v", err)
	}
	defer reader.Close()

	log.Println("Waiting for events..")
	log.Printf("%-15s %-6s -> %-15s %-6s",
		"Src addr",
		"Port",
		"Dest addr",
		"Port",
	)
	go readePackets(reader)

	<-setupSignalChannel()
	log.Println("Exiting...")
}

func setupSignalChannel() <-chan os.Signal {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	return sigs
}

func readePackets(reader *perf.Reader) {
	var packet ebpf.Packet
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a packet structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &packet); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("%-15s %-6d -> %-15s %-6d",
			intToIP(packet.SourceIp),
			packet.SourcePort,
			intToIP(packet.DestinationIp),
			packet.DestinationPort,
		)
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}
