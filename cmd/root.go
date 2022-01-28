package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = cobra.Command{
	Use:  "fwrouter",
	Long: "An in-kernel traffic router for Azure Firewall based on eBPF/XDP.",
}

func init() {
	rootCmd.AddCommand(&runCmd)
}

func Execute() error {
	return rootCmd.Execute()
}
