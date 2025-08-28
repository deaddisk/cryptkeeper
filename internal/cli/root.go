// Package cli provides command-line interface implementation for cryptkeeper.
package cli

import (
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "cryptkeeper",
	Short: "A CLI tool for evidence collection and secure upload",
	Long: `cryptkeeper is a CLI tool for collecting evidence artifacts and securely 
uploading them to various destinations with encryption support.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Show help and exit 0 if no subcommand is provided
		cmd.Help()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Add subcommands
	rootCmd.AddCommand(harvestCmd)
}