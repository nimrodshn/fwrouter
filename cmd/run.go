package cmd

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"fwrouter/pkg/ebpf"

	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
)

var runCmd = cobra.Command{
	Use:   "run",
	Short: "Runs the in-kernel FW router",
	Run:   runRouter,
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

	log.Println("Waiting for events..")
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()

	<-done
	fmt.Println("Exiting...")
}
